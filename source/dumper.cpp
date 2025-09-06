#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <array>

struct material {
    const char* label;
    uint32_t address;
    const char* name;
};

auto favorite_materials = std::to_array<material>({
    { "Red (Vischeck)", 0, "Glow_Red" },
    { "Blue (Vischeck)", 0, "emissive_laser_blue_colourblind" },
    { "White", 0, "manpad_crt_hdr" }
});

HANDLE open_rust_client_process() {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::println(std::cerr, "Failed to create process snapshot. Error code: {}", GetLastError());
        return nullptr;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    HANDLE process = nullptr;

    for (bool success = Process32FirstW(snapshot, &entry); success; success = Process32NextW(snapshot, &entry)) {
        if (_wcsicmp(entry.szExeFile, L"RustClient.exe") == 0) {
            process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
            if (!process) {
                std::println(std::cerr, "Failed to open RustClient.exe. Error code: {}", GetLastError());
            }
            break;
        }
    }

    CloseHandle(snapshot);

    if (!process) {
        std::println(std::cerr, "RustClient.exe not found.");
    }

    return process;
}

struct MemoryRegion {
    uintptr_t base;
    size_t size;
};

std::vector<MemoryRegion> get_memory_regions(HANDLE process) {
    std::vector<MemoryRegion> regions;
    MEMORY_BASIC_INFORMATION memory_info{};
    uintptr_t address = 0;

    while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &memory_info, sizeof(memory_info))) {
        if (memory_info.State == MEM_COMMIT &&
            memory_info.Type == MEM_PRIVATE &&
            !(memory_info.Protect & PAGE_NOACCESS) &&
            !(memory_info.Protect & PAGE_GUARD) &&
            (memory_info.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_READONLY)) &&
            memory_info.RegionSize >= 0x1000) {
            regions.emplace_back(MemoryRegion{ reinterpret_cast<uintptr_t>(memory_info.BaseAddress), memory_info.RegionSize });
        }
        address += memory_info.RegionSize;
    }

    std::ranges::sort(regions, std::ranges::greater{}, &MemoryRegion::size);
    return regions;
}

std::vector<uintptr_t> pattern_scan(HANDLE process, uintptr_t start, size_t size) {
    std::vector<uintptr_t> matches;
    constexpr size_t chunk_size = 0x40000;
    constexpr size_t alignment = sizeof(uint64_t);
    static thread_local BYTE buffer[chunk_size + alignment];

    for (size_t offset = 0; offset < size; offset += chunk_size) {
        const size_t max_readable = (offset + chunk_size + alignment <= size) ? chunk_size + alignment : size - offset;

        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(start + offset), buffer, max_readable, nullptr)) continue;

        for (size_t i = 0; i <= max_readable - alignment; ++i) {
            if (buffer[i] == 0xEF && *reinterpret_cast<const uint64_t*>(buffer + i) == 0xDEADBEEFDEADBEEF) {
                matches.push_back(start + offset + i);
            }
        }
    }

    return matches;
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    const auto process = open_rust_client_process();
    if (!process) return 1;

    const auto regions = get_memory_regions(process);

    std::mutex map_mutex, output_mutex;
    std::atomic<size_t> region_index = 0;
    std::vector<std::thread> threads;
    std::atomic<int> total_materials = 0;
    std::ofstream output("output.txt");

    for (unsigned int t = 0; t < std::thread::hardware_concurrency(); ++t) {
        threads.emplace_back([&]() {
            while (true) {
                size_t i = region_index.fetch_add(1);
                if (i >= regions.size()) break;

                const MemoryRegion& region = regions[i];
                const auto matches = pattern_scan(process, region.base, region.size);

                for (const auto& match : matches) {
                    const uintptr_t base = match - 0x88;

                    uintptr_t name_ptr{};
                    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + 0x30), &name_ptr, sizeof(name_ptr), nullptr)) continue;

                    char name_buffer[255]{};
                    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(name_ptr), name_buffer, sizeof(name_buffer) - 1, nullptr)) continue;
                    const std::string_view material_name(name_buffer);

                    uint32_t key{};
                    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + 0x8), &key, sizeof(key), nullptr)) continue;
                    
                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if (const auto it = std::ranges::find(favorite_materials, material_name, &material::name); it != favorite_materials.end()) {
                            it->address = key;
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lock(output_mutex);
                        std::println(output, "{} {}", material_name, key);
                    }

                    total_materials++;
                }
            }
        });
    }
    for (auto& thread : threads) thread.join();
    CloseHandle(process);

    std::println(std::cout, "{} materials saved to output.txt", total_materials.load());
    std::println(std::cout, "\nconstexpr auto materials = std::to_array<material>({{");
    for (const auto& m : favorite_materials) {
        if (m.address)
            std::println(std::cout, "    {{ \"{}\", {} }}, // {}", m.label, m.address, m.name);
    }
    std::println(std::cout, "}});");

    return 0;
}