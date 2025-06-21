#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <mutex>
#include <algorithm>

struct material {
    std::string label;
    uint32_t address;
    std::string name;
};

std::vector<material> favorite_materials = {
    { "Red (Vischeck)", 0, "Glow_Red" },
    { "Blue (Vischeck)", 0, "emissive_laser_blue_colourblind" },
    { "White", 0, "manpad_crt_hdr" }
};

HANDLE open_rust_client_process() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error code: " << GetLastError() << "\n";
        return nullptr;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    HANDLE process = nullptr;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"RustClient.exe") == 0) {
                process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
                if (!process) {
                    std::cerr << "Failed to open process. Error code: " << GetLastError() << "\n";
                }
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (!process) {
        std::cerr << "RustClient.exe not found.\n";
    }
    return process;
}

std::vector<std::pair<uintptr_t, size_t>> get_memory_regions(HANDLE process) {
    std::vector<std::pair<uintptr_t, size_t>> regions;
    MEMORY_BASIC_INFORMATION memory_info{};
    uintptr_t address = 0;

    while (VirtualQueryEx(process, (LPCVOID)address, &memory_info, sizeof(memory_info))) {
        if (memory_info.State == MEM_COMMIT &&
            memory_info.Type == MEM_PRIVATE &&
            !(memory_info.Protect & PAGE_NOACCESS) &&
            !(memory_info.Protect & PAGE_GUARD) &&
            (memory_info.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_READONLY)) &&
            memory_info.RegionSize >= 0x1000) {
            regions.emplace_back((uintptr_t)memory_info.BaseAddress, memory_info.RegionSize);
        }
        address += memory_info.RegionSize;
    }

    std::sort(regions.begin(), regions.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    return regions;
}

std::vector<uintptr_t> pattern_scan_simd(HANDLE process, uintptr_t start, size_t size) {
    std::vector<uintptr_t> matches;
    static thread_local BYTE buffer[0x40000 + 8];

    for (size_t offset = 0; offset < size; offset += 0x40000) {
        size_t max_readable = (offset + 0x40000 + 8 <= size) ? 0x40000 + 8 : size - offset;

        if (!ReadProcessMemory(process, (LPCVOID)(start + offset), buffer, max_readable, nullptr))
            continue;

        for (size_t i = 0; i <= max_readable - 8; ++i) {
            if (buffer[i] == 0xEF && *(const uint64_t*)(buffer + i) == 0xDEADBEEFDEADBEEF) {
                matches.push_back(start + offset + i);
            }
        }
    }
    return matches;
}

int main() {
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    HANDLE process = open_rust_client_process();
    if (!process) return 1;

    std::vector<std::pair<uintptr_t, size_t>> regions = get_memory_regions(process);

    std::mutex map_mutex, output_mutex;
    std::atomic<size_t> region_index = 0;
    std::vector<std::thread> threads;
    std::atomic<int> total_materials = 0;
    std::ofstream output("output.txt");

    for (size_t t = 0; t < std::thread::hardware_concurrency(); ++t) {
        threads.emplace_back([&]() {
            while (true) {
                size_t i = region_index.fetch_add(1);
                if (i >= regions.size()) break;

                auto& region = regions[i];
                auto matches = pattern_scan_simd(process, region.first, region.second);

                for (const auto& match : matches) {
                    uintptr_t base = match - 0x88;

                    uintptr_t name_ptr;
                    if (!ReadProcessMemory(process, (LPCVOID)(base + 0x30), &name_ptr, sizeof(name_ptr), nullptr)) continue;

                    char name_buffer[255] = { 0 };
                    if (!ReadProcessMemory(process, (LPCVOID)name_ptr, name_buffer, sizeof(name_buffer) - 1, nullptr)) continue;

                    uint32_t key;
                    if (!ReadProcessMemory(process, (LPCVOID)(base + 0x8), &key, sizeof(key), nullptr)) continue;

                    std::string material_name(name_buffer);

                    {
                        std::lock_guard<std::mutex> lock(map_mutex);
                        if (auto it = std::find_if(favorite_materials.begin(), favorite_materials.end(),
                            [&](const material& m) { return m.name == material_name; }); it != favorite_materials.end()) {

                            it->address = key;
                        }
                    }

                    {
                        std::lock_guard<std::mutex> lock(output_mutex);
                        output << material_name << " " << key << "\n";
                    }

                    total_materials++;
                }
            }
            });
    }
    for (auto& thread : threads) thread.join();
    CloseHandle(process);

    std::cout << total_materials << " materials saved to output.txt\n";
    std::cout << "\ninline const std::vector<material> materials = {\n";
    for (const auto& material : favorite_materials) {
        if (material.address != 0) {
            std::cout << "    { \"" << material.label << "\", " << material.address << " }, // " << material.name << "\n";
        }
    }
    std::cout << "};\n";

    return 0;
}