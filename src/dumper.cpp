#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <mutex>
#include <array>
#include <execution>

using VolkHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype([](HANDLE h) noexcept { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); })>;

VolkHandle open_rust_client_process() {
    VolkHandle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if (!snapshot || snapshot.get() == INVALID_HANDLE_VALUE) {
        std::println(std::cerr, "Failed to create process snapshot. Error code: {}", GetLastError());
        return {};
    }

    PROCESSENTRY32W entry{ sizeof(entry) };
    if (Process32FirstW(snapshot.get(), &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"RustClient.exe") == 0) {
                if (auto h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID)) {
                    return VolkHandle{ h };
                }
                else {
                    std::println(std::cerr, "OpenProcess failed for PID {}. GetLastError={}", entry.th32ProcessID, GetLastError());
                }
            }
        } while (Process32NextW(snapshot.get(), &entry));
    }

    std::println(std::cerr, "RustClient.exe not found.");
    return {};
}

struct MemoryRegion {
    std::uintptr_t base;
    std::size_t    size;
};

std::vector<MemoryRegion> get_memory_regions(const VolkHandle& process) {
    std::vector<MemoryRegion> regions{};

    std::uintptr_t address{};
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQueryEx(process.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_READONLY)) &&
            mbi.RegionSize >= 0x1000) {
            regions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);
        }
        address += mbi.RegionSize;
    }

    std::ranges::sort(regions, std::ranges::greater{}, &MemoryRegion::size);
    return regions;
}

std::vector<std::uintptr_t> pattern_scan(const VolkHandle& process, std::uintptr_t start, std::size_t size) {
    static constexpr auto pattern = std::to_array<std::byte>({
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE},
        std::byte{0xEF}, std::byte{0xBE}, std::byte{0xAD}, std::byte{0xDE}
    });

    static constexpr std::size_t chunk_size = 0x40000;

    std::vector<std::uintptr_t> matches;
    std::vector<std::byte> read_buffer(chunk_size + pattern.size() - 1);

    for (std::size_t offset = 0; offset < size; offset += chunk_size) {
        const std::size_t bytes_to_read = std::min(chunk_size + pattern.size() - 1, size - offset);

        SIZE_T bytes_read{};
        if (!ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(start + offset), read_buffer.data(), bytes_to_read, &bytes_read) || bytes_read < pattern.size()) continue;

        const auto* data = read_buffer.data();
        for (std::size_t i = 0; i < bytes_read - pattern.size() + 1; ++i) {
            if (data[i] != pattern.front()) continue;
            if (data[i + pattern.size() - 1] != pattern.back()) continue;

            if (std::equal(data + i, data + i + pattern.size(), pattern.data())) {
                matches.push_back(start + offset + i);
            }
        }
    }

    return matches;
}

struct Material {
    const char*   label;
    std::uint32_t id;
    const char*   name;
};

auto favorite_materials = std::to_array<Material>({
    { "Red (Vischeck)", 0, "Glow_Red" },
    { "Blue (Vischeck)", 0, "emissive_laser_blue_colourblind" },
    { "White", 0, "manpad_crt_hdr" }
});

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    const auto process = open_rust_client_process();
    if (!process) return 1;

    const auto regions = get_memory_regions(process);

    std::mutex map_mutex, output_mutex;
    std::ofstream output("output.txt");
    const int total_materials = std::transform_reduce(
        std::execution::par,
        regions.begin(),
        regions.end(),
        0,
        std::plus<>{},
        [&](const MemoryRegion& region) {
            int local = 0;

            const auto matches = pattern_scan(process, region.base, region.size);
            for (const auto& match : matches) {
                const std::uintptr_t base = match - 0x88;

                std::uint32_t id{};
                if (!ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(base + 0x8), &id, sizeof(id), nullptr)) continue;

                std::uintptr_t name_ptr{};
                if (!ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(base + 0x30), &name_ptr, sizeof(name_ptr), nullptr)) continue;

                char name_buffer[255]{};
                if (!ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(name_ptr), name_buffer, sizeof(name_buffer) - 1, nullptr)) continue;
                const std::string_view material_name(name_buffer);

                if (const auto it = std::ranges::find(favorite_materials, material_name, &Material::name); it != favorite_materials.end()) {
                    std::lock_guard lock(map_mutex);
                    it->id = id;
                }

                { std::lock_guard lock(output_mutex); std::println(output, "{} {}", material_name, id); }

                ++local;
            }

            return local;
        }
    );
    
    std::println(std::cout, "{} materials saved to output.txt", total_materials);
    std::println(std::cout, "\nconstexpr auto materials = std::to_array<material>({{");
    for (const auto& material : favorite_materials) {
        if (material.id) std::println(std::cout, "    {{ \"{}\", {} }}, // {}", material.label, material.id, material.name);
    }
    std::println(std::cout, "}});");

    return 0;
}