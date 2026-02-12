/*
 * run_pk_converter.cpp
 *
 * Converts a standard proving key to a raw binary format that can be loaded
 * much faster (no parsing, no sqrt computation for point decompression).
 *
 * Run this ONCE on your PC after keygen, then use the converted file on Jetson.
 *
 * Usage:
 *   ./run_pk_converter <proving_key.bin> <proving_key_raw.bin>
 *
 * The raw format is NOT portable across:
 *   - Different architectures (endianness)
 *   - Different compilers (struct padding)
 *   - Different libff builds (Montgomery form parameters)
 *
 * Both the converter and prover must use the SAME libff build.
 */

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <cstdio>
#include <cstring>

using namespace std;
using namespace chrono;
using namespace libsnark;

typedef default_r1cs_gg_ppzksnark_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef libff::G1<ppT> G1;
typedef libff::G2<ppT> G2;

// Magic number to identify our raw format
const uint64_t RAW_PK_MAGIC = 0x5A454B5241504B31ULL; // "ZEKAPK1" + version
const uint32_t RAW_PK_VERSION = 1;

/*
 * Raw proving key header
 */
struct RawPKHeader
{
    uint64_t magic;
    uint32_t version;
    uint32_t flags; // Reserved for future use

    // Sizes of each component
    uint64_t A_query_size;
    uint64_t B_query_g1_size;
    uint64_t B_query_g2_size;
    uint64_t H_query_size;
    uint64_t L_query_size;

    // Size info for validation
    uint64_t g1_point_size;
    uint64_t g2_point_size;

    // Constraint system info
    uint64_t cs_num_constraints;
    uint64_t cs_num_variables;
    uint64_t cs_primary_input_size;
    uint64_t cs_auxiliary_input_size;
};

/*
 * Write a vector of G1 points as raw binary
 */
template <typename GroupT>
bool write_raw_points(FILE *f, const vector<GroupT> &points)
{
    size_t count = points.size();

    if (count == 0)
    {
        return true;
    }

    // Write all points as raw memory
    size_t bytes_written = fwrite(points.data(), sizeof(GroupT), count, f);

    if (bytes_written != count)
    {
        cerr << "ERROR: Failed to write points. Expected " << count
             << ", wrote " << bytes_written << endl;
        return false;
    }

    return true;
}

/*
 * Write a single point as raw binary
 */
template <typename GroupT>
bool write_raw_point(FILE *f, const GroupT &point)
{
    size_t bytes_written = fwrite(&point, sizeof(GroupT), 1, f);
    return bytes_written == 1;
}

/*
 * Convert proving key to raw binary format
 */
bool convert_pk_to_raw(const r1cs_gg_ppzksnark_proving_key<ppT> &pk,
                       const string &output_file)
{

    FILE *f = fopen(output_file.c_str(), "wb");
    if (!f)
    {
        cerr << "ERROR: Could not open output file: " << output_file << endl;
        return false;
    }

    cout << "Writing raw binary format..." << endl;

    // Prepare header
    RawPKHeader header;
    memset(&header, 0, sizeof(header));

    header.magic = RAW_PK_MAGIC;
    header.version = RAW_PK_VERSION;
    header.flags = 0;

    header.A_query_size = pk.A_query.size();
    header.B_query_g1_size = pk.B_query.values.size();
    header.B_query_g2_size = pk.B_query.indices.size();
    header.H_query_size = pk.H_query.size();
    header.L_query_size = pk.L_query.size();

    header.g1_point_size = sizeof(G1);
    header.g2_point_size = sizeof(G2);

    header.cs_num_constraints = pk.constraint_system.num_constraints();
    header.cs_num_variables = pk.constraint_system.num_variables();
    header.cs_primary_input_size = pk.constraint_system.primary_input_size;
    header.cs_auxiliary_input_size = pk.constraint_system.auxiliary_input_size;

    // Write header
    if (fwrite(&header, sizeof(header), 1, f) != 1)
    {
        cerr << "ERROR: Failed to write header" << endl;
        fclose(f);
        return false;
    }

    cout << "  Header written (" << sizeof(header) << " bytes)" << endl;

    // Write individual G1/G2 elements
    cout << "  Writing scalar elements..." << endl;
    if (!write_raw_point(f, pk.alpha_g1))
    {
        fclose(f);
        return false;
    }
    if (!write_raw_point(f, pk.beta_g1))
    {
        fclose(f);
        return false;
    }
    if (!write_raw_point(f, pk.beta_g2))
    {
        fclose(f);
        return false;
    }
    if (!write_raw_point(f, pk.delta_g1))
    {
        fclose(f);
        return false;
    }
    if (!write_raw_point(f, pk.delta_g2))
    {
        fclose(f);
        return false;
    }

    // Write A_query
    cout << "  Writing A_query (" << header.A_query_size << " G1 points, "
         << (header.A_query_size * sizeof(G1) / 1024 / 1024) << " MB)..." << endl;
    if (!write_raw_points(f, pk.A_query))
    {
        fclose(f);
        return false;
    }

    // Write B_query (two parts: values=G1, indices=G2)
    cout << "  Writing B_query.values (" << header.B_query_g1_size << " G1 points)..." << endl;
    if (!write_raw_points(f, pk.B_query.values))
    {
        fclose(f);
        return false;
    }

    cout << "  Writing B_query.indices (" << header.B_query_g2_size << " G2 points)..." << endl;
    if (!write_raw_points(f, pk.B_query.indices))
    {
        fclose(f);
        return false;
    }

    // Write H_query
    cout << "  Writing H_query (" << header.H_query_size << " G1 points, "
         << (header.H_query_size * sizeof(G1) / 1024 / 1024) << " MB)..." << endl;
    if (!write_raw_points(f, pk.H_query))
    {
        fclose(f);
        return false;
    }

    // Write L_query
    cout << "  Writing L_query (" << header.L_query_size << " G1 points, "
         << (header.L_query_size * sizeof(G1) / 1024 / 1024) << " MB)..." << endl;
    if (!write_raw_points(f, pk.L_query))
    {
        fclose(f);
        return false;
    }

    // Write constraint system using standard serialization
    // (This is small compared to the queries)
    cout << "  Writing constraint system..." << endl;
    long cs_start = ftell(f);

    // We'll use a temp file for the constraint system since it uses stream operators
    string cs_temp = output_file + ".cs_temp";
    {
        ofstream cs_ofs(cs_temp, ios::binary);
        cs_ofs << pk.constraint_system;
        cs_ofs.close();
    }

    // Read temp file and append to main file
    ifstream cs_ifs(cs_temp, ios::binary | ios::ate);
    size_t cs_size = cs_ifs.tellg();
    cs_ifs.seekg(0);
    vector<char> cs_buffer(cs_size);
    cs_ifs.read(cs_buffer.data(), cs_size);
    cs_ifs.close();

    // Write CS size then data
    fwrite(&cs_size, sizeof(cs_size), 1, f);
    fwrite(cs_buffer.data(), 1, cs_size, f);

    // Clean up temp file
    remove(cs_temp.c_str());

    long file_size = ftell(f);
    fclose(f);

    cout << "  Constraint system written (" << (cs_size / 1024 / 1024) << " MB)" << endl;
    cout << endl;
    cout << "Total file size: " << (file_size / 1024 / 1024) << " MB" << endl;

    return true;
}

void print_usage(const char *progname)
{
    cout << "Proving Key Converter - Standard to Raw Binary Format" << endl;
    cout << endl;
    cout << "Usage: " << progname << " <proving_key.bin> <proving_key_raw.bin>" << endl;
    cout << endl;
    cout << "This tool converts a standard proving key to a raw binary format" << endl;
    cout << "that can be loaded much faster (no parsing, no sqrt for decompression)." << endl;
    cout << endl;
    cout << "Performance:" << endl;
    cout << "  Standard format loading: ~20 seconds" << endl;
    cout << "  Raw format loading:      ~2-3 seconds" << endl;
    cout << endl;
    cout << "IMPORTANT: The raw format is platform-specific!" << endl;
    cout << "  - Run this converter on the SAME platform where you'll run the prover" << endl;
    cout << "  - Or ensure both machines have identical: architecture, compiler, libff build" << endl;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        print_usage(argv[0]);
        return 1;
    }

    string input_file = argv[1];
    string output_file = argv[2];

    cout << "========================================" << endl;
    cout << "Proving Key Converter" << endl;
    cout << "========================================" << endl;
    cout << endl;
    cout << "Input:  " << input_file << endl;
    cout << "Output: " << output_file << endl;
    cout << endl;

    // Initialize libsnark
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // Load standard proving key
    cout << "Loading standard proving key..." << endl;
    cout << "(This is slow due to point decompression - that's why we're converting!)" << endl;
    cout << endl;

    auto load_start = steady_clock::now();

    r1cs_gg_ppzksnark_proving_key<ppT> pk;
    ifstream pk_ifs(input_file, ios::binary);
    if (!pk_ifs.good())
    {
        cerr << "ERROR: Could not open input file: " << input_file << endl;
        return 1;
    }
    pk_ifs >> pk;
    pk_ifs.close();

    auto load_end = steady_clock::now();
    auto load_time = duration_cast<milliseconds>(load_end - load_start).count();

    cout << "Loaded in " << (load_time / 1000.0) << " seconds" << endl;
    cout << endl;

    // Print statistics
    cout << "Proving key statistics:" << endl;
    cout << "  alpha_g1, beta_g1, delta_g1: 3 G1 points" << endl;
    cout << "  beta_g2, delta_g2: 2 G2 points" << endl;
    cout << "  A_query: " << pk.A_query.size() << " G1 points" << endl;
    cout << "  B_query: " << pk.B_query.first.size() << " G1 + "
         << pk.B_query.second.size() << " G2 points" << endl;
    cout << "  H_query: " << pk.H_query.size() << " G1 points" << endl;
    cout << "  L_query: " << pk.L_query.size() << " G1 points" << endl;
    cout << endl;
    cout << "  sizeof(G1): " << sizeof(G1) << " bytes" << endl;
    cout << "  sizeof(G2): " << sizeof(G2) << " bytes" << endl;
    cout << endl;

    // Convert to raw format
    auto convert_start = steady_clock::now();

    if (!convert_pk_to_raw(pk, output_file))
    {
        cerr << "Conversion failed!" << endl;
        return 1;
    }

    auto convert_end = steady_clock::now();
    auto convert_time = duration_cast<milliseconds>(convert_end - convert_start).count();

    cout << endl;
    cout << "========================================" << endl;
    cout << "Conversion completed!" << endl;
    cout << "========================================" << endl;
    cout << "  Load time:    " << (load_time / 1000.0) << " seconds" << endl;
    cout << "  Convert time: " << (convert_time / 1000.0) << " seconds" << endl;
    cout << endl;
    cout << "Output file: " << output_file << endl;
    cout << endl;
    cout << "Use this file with run_prover_optimized_raw for fastest loading." << endl;

    return 0;
}