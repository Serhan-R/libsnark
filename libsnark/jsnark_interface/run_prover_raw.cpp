/*
 * run_prover_raw.cpp
 *
 * Prover that loads proving key from raw binary format for fastest possible loading.
 * The raw format is generated directly by run_keygen_only.
 *
 * Performance comparison:
 *   Standard format: ~20-24 seconds to load PK (parsing + sqrt for decompression)
 *   Raw format:      ~2-3 seconds to load PK (just fread!)
 *
 * Usage:
 *   ./run_prover_raw <circuit.arith> <proving_key_raw.bin> <circuit_metadata.bin> <input.in> <output_dir>
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include "FastWitnessEvaluator.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstdio>
#include <cstring>

using namespace std;
using namespace chrono;
using namespace libsnark;

typedef default_r1cs_gg_ppzksnark_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef libff::G1<ppT> G1;
typedef libff::G2<ppT> G2;

// Must match run_keygen_only.cpp
const uint64_t RAW_PK_MAGIC = 0x5A454B5241504B31ULL;
const uint32_t RAW_PK_VERSION = 1;

struct RawPKHeader
{
    uint64_t magic;
    uint32_t version;
    uint32_t flags;
    uint64_t A_query_size;
    uint64_t B_query_g1_size;
    uint64_t B_query_g2_size;
    uint64_t H_query_size;
    uint64_t L_query_size;
    uint64_t g1_point_size;
    uint64_t g2_point_size;
    uint64_t cs_num_constraints;
    uint64_t cs_num_variables;
    uint64_t cs_primary_input_size;
    uint64_t cs_auxiliary_input_size;
};

/*
 * Read a vector of points from raw binary
 */
template <typename GroupT>
bool read_raw_points(FILE *f, vector<GroupT> &points, size_t count)
{
    points.resize(count);

    if (count == 0)
    {
        return true;
    }

    size_t read = fread(points.data(), sizeof(GroupT), count, f);
    if (read != count)
    {
        cerr << "ERROR: Expected " << count << " points, read " << read << endl;
        return false;
    }

    return true;
}

/*
 * Read a single point from raw binary
 */
template <typename GroupT>
bool read_raw_point(FILE *f, GroupT &point)
{
    size_t read = fread(&point, sizeof(GroupT), 1, f);
    return read == 1;
}

/*
 * Load proving key from raw binary format - FAST!
 */
bool load_pk_raw(const string &filename, r1cs_gg_ppzksnark_proving_key<ppT> &pk)
{
    FILE *f = fopen(filename.c_str(), "rb");
    if (!f)
    {
        cerr << "ERROR: Could not open raw PK file: " << filename << endl;
        return false;
    }

    // Read and validate header
    RawPKHeader header;
    if (fread(&header, sizeof(header), 1, f) != 1)
    {
        cerr << "ERROR: Failed to read header" << endl;
        fclose(f);
        return false;
    }

    if (header.magic != RAW_PK_MAGIC)
    {
        cerr << "ERROR: Invalid magic number. Not a raw PK file." << endl;
        cerr << "  Expected: 0x" << hex << RAW_PK_MAGIC << endl;
        cerr << "  Got:      0x" << hex << header.magic << dec << endl;
        fclose(f);
        return false;
    }

    if (header.version != RAW_PK_VERSION)
    {
        cerr << "ERROR: Version mismatch. Expected " << RAW_PK_VERSION
             << ", got " << header.version << endl;
        fclose(f);
        return false;
    }

    // Validate struct sizes match
    if (header.g1_point_size != sizeof(G1))
    {
        cerr << "ERROR: G1 size mismatch! File was created with different libff build." << endl;
        cerr << "  File says: " << header.g1_point_size << " bytes" << endl;
        cerr << "  This build: " << sizeof(G1) << " bytes" << endl;
        fclose(f);
        return false;
    }

    if (header.g2_point_size != sizeof(G2))
    {
        cerr << "ERROR: G2 size mismatch! File was created with different libff build." << endl;
        fclose(f);
        return false;
    }

    cout << "  Raw PK header validated. Loading..." << endl;
    cout << "    A_query: " << header.A_query_size << " G1 points" << endl;
    cout << "    B_query: " << header.B_query_g1_size << " G1 + "
         << header.B_query_g2_size << " G2 points" << endl;
    cout << "    H_query: " << header.H_query_size << " G1 points" << endl;
    cout << "    L_query: " << header.L_query_size << " G1 points" << endl;

    // Read scalar elements
    if (!read_raw_point(f, pk.alpha_g1))
    {
        fclose(f);
        return false;
    }
    if (!read_raw_point(f, pk.beta_g1))
    {
        fclose(f);
        return false;
    }
    if (!read_raw_point(f, pk.beta_g2))
    {
        fclose(f);
        return false;
    }
    if (!read_raw_point(f, pk.delta_g1))
    {
        fclose(f);
        return false;
    }
    if (!read_raw_point(f, pk.delta_g2))
    {
        fclose(f);
        return false;
    }

    // Read queries - this is the bulk of the data
    auto t1 = steady_clock::now();

    if (!read_raw_points(f, pk.A_query, header.A_query_size))
    {
        fclose(f);
        return false;
    }

    auto t2 = steady_clock::now();
    cout << "    A_query loaded in "
         << duration_cast<milliseconds>(t2 - t1).count() << " ms" << endl;

    if (!read_raw_points(f, pk.B_query.values, header.B_query_g1_size))
    {
        fclose(f);
        return false;
    }
    if (!read_raw_points(f, pk.B_query.indices, header.B_query_g2_size))
    {
        fclose(f);
        return false;
    }

    auto t3 = steady_clock::now();
    cout << "    B_query loaded in "
         << duration_cast<milliseconds>(t3 - t2).count() << " ms" << endl;

    if (!read_raw_points(f, pk.H_query, header.H_query_size))
    {
        fclose(f);
        return false;
    }

    auto t4 = steady_clock::now();
    cout << "    H_query loaded in "
         << duration_cast<milliseconds>(t4 - t3).count() << " ms" << endl;

    if (!read_raw_points(f, pk.L_query, header.L_query_size))
    {
        fclose(f);
        return false;
    }

    auto t5 = steady_clock::now();
    cout << "    L_query loaded in "
         << duration_cast<milliseconds>(t5 - t4).count() << " ms" << endl;

    // Read constraint system size and data
    size_t cs_size;
    if (fread(&cs_size, sizeof(cs_size), 1, f) != 1)
    {
        cerr << "ERROR: Failed to read CS size" << endl;
        fclose(f);
        return false;
    }

    vector<char> cs_buffer(cs_size);
    if (fread(cs_buffer.data(), 1, cs_size, f) != cs_size)
    {
        cerr << "ERROR: Failed to read constraint system" << endl;
        fclose(f);
        return false;
    }

    // Parse constraint system using standard deserialization
    // (This is small compared to the queries, so standard format is fine)
    string cs_str(cs_buffer.begin(), cs_buffer.end());
    istringstream cs_iss(cs_str);
    cs_iss >> pk.constraint_system;

    auto t6 = steady_clock::now();
    cout << "    Constraint system loaded in "
         << duration_cast<milliseconds>(t6 - t5).count() << " ms" << endl;

    fclose(f);
    return true;
}

void print_usage(const char *progname)
{
    cout << "ZEKRA Prover with Raw Binary PK Loading" << endl;
    cout << endl;
    cout << "Usage: " << progname << " <circuit.arith> <proving_key_raw.bin> <input.in> <output_dir>" << endl;
    cout << endl;
    cout << "Arguments:" << endl;
    cout << "  circuit.arith         Circuit file" << endl;
    cout << "  proving_key_raw.bin   Raw binary proving key (from run_keygen_only)" << endl;
    cout << "  circuit_metadata.bin  Path to pre-serialized circuit metadata" << endl;
    cout << "  input.in              Witness/input file" << endl;
    cout << "  output_dir            Directory to save proof" << endl;
    cout << endl;
    cout << "Performance: ~2-3 seconds PK loading (vs ~20 seconds for standard format)" << endl;
}

int main(int argc, char **argv)
{
    libff::enter_block("ZEKRA Prover (Raw PK Format)");

    if (argc != 6)
    {
        print_usage(argv[0]);
        return 1;
    }

    char *arith_file = argv[1];
    char *pk_raw_file = argv[2];
    char *meta_file = argv[3]; 
    char *input_file = argv[4];
    char *output_dir = argv[5];

    cout << "========================================" << endl;
    cout << "ZEKRA Prover (Raw PK Format)" << endl;
    cout << "========================================" << endl;
    cout << endl;

    auto total_start = steady_clock::now();

    // Initialize
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    gadgetlib2::initPublicParamsFromDefaultPp();

    // Step 1: Load raw proving key
    cout << "[1/3] Loading proving key (raw format)..." << endl;
    auto pk_start = steady_clock::now();

    r1cs_gg_ppzksnark_proving_key<ppT> pk;
    if (!load_pk_raw(pk_raw_file, pk))
    {
        cerr << "Failed to load proving key!" << endl;
        return 1;
    }

    auto pk_end = steady_clock::now();
    auto pk_time = duration_cast<milliseconds>(pk_end - pk_start).count();
    cout << "  Proving key loaded in " << pk_time << " ms" << endl;
    cout << endl;

    // Load circuit metadata
    cout << "[1.5] Loading circuit metadata..." << endl;
    auto md_start = steady_clock::now();
    CircuitMetadata metadata;
    ifstream meta_ifs(meta_file, ios::binary);
    if (!meta_ifs.good())
    {
        cerr << "ERROR: Could not open metadata: " << meta_file << endl;
        return 1;
    }
    metadata.deserialize(meta_ifs);
    meta_ifs.close();
    auto md_end = steady_clock::now();
    auto md_time = duration_cast<milliseconds>(md_end - md_start).count();
    cout << "  Metadata loaded in " << md_time << " ms" << endl;
    cout << endl;

    // Step 2: Evaluate circuit with input (Fast Path)
    cout << "[2/3] Evaluating circuit (Fast Path)..." << endl;
    auto eval_start = steady_clock::now();

    // 1. Fast witness evaluation
    FastWitnessEvaluator evaluator;
    evaluator.evaluate(arith_file, input_file);

    // 2. Build the variable assignment vector
    vector<FieldT> full_assignment;
    // Use the CS we just loaded into the 'pk' object
    size_t expectedSize = pk.constraint_system.num_variables();
    evaluator.buildAssignment(metadata, full_assignment, expectedSize);

    // 3. Extract primary and auxiliary inputs using the CS from the PK
    size_t num_primary = pk.constraint_system.num_inputs();

    r1cs_primary_input<FieldT> primary_input(
        full_assignment.begin(),
        full_assignment.begin() + num_primary);

    r1cs_auxiliary_input<FieldT> auxiliary_input(
        full_assignment.begin() + num_primary,
        full_assignment.end());

    auto eval_end = steady_clock::now();
    cout << "  Circuit evaluated in "
         << duration_cast<milliseconds>(eval_end - eval_start).count() << " ms" << endl;
    cout << "  Primary inputs: " << primary_input.size() << endl;
    cout << "  Auxiliary inputs: " << auxiliary_input.size() << endl;
    cout << endl;

    // Step 3: Generate proof
    cout << "[3/3] Generating proof..." << endl;
    auto prove_start = steady_clock::now();

    r1cs_gg_ppzksnark_proof<ppT> proof =
        r1cs_gg_ppzksnark_prover<ppT>(pk, primary_input, auxiliary_input);

    auto prove_end = steady_clock::now();
    auto prove_time = duration_cast<milliseconds>(prove_end - prove_start).count();
    cout << "  Proof generated in " << prove_time << " ms" << endl;
    cout << endl;

    // Save proof
    string proof_file = string(output_dir) + "/proof.bin";
    {
        ofstream proof_ofs(proof_file, ios::binary);
        proof_ofs << proof;
    }
    cout << "Proof saved to: " << proof_file << endl;

    // Summary
    auto total_end = steady_clock::now();
    auto total_time = duration_cast<milliseconds>(total_end - total_start).count();

    libff::leave_block("ZEKRA Prover (Raw PK Format)");

    cout << endl;
    cout << "========================================" << endl;
    cout << "Summary" << endl;
    cout << "========================================" << endl;
    cout << "  PK loading:     " << pk_time << " ms" << endl;
    cout << "  Evaluation:     " << duration_cast<milliseconds>(eval_end - eval_start).count() << " ms" << endl;
    cout << "  Proof gen:      " << prove_time << " ms" << endl;
    cout << "  Total:          " << total_time << " ms" << endl;
    cout << endl;

    return 0;
}