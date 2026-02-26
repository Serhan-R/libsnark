/*
 * run_keygen_raw.cpp
 *
 * Modified from run_ppzksnark.cpp to run only the keygen (generator) stage
 * Saves the proving and verification keys to disk for later use
 *
 * Now supports TWO output formats for proving key:
 *   1. Raw binary format (proving_key_raw.bin) - Fast loading 
 *   2. Standard format (proving_key.bin) - Portable but slow loading 
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <iostream>
#include <fstream>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <cstdio>

using namespace std;
using namespace chrono;

typedef libsnark::default_r1cs_gg_ppzksnark_pp ppT;
typedef libff::G1<ppT> G1;
typedef libff::G2<ppT> G2;
typedef libff::Fr<ppT> FieldT;

// ============================================================================
// Raw Binary Format Definitions
// ============================================================================

// Magic number to identify our raw format: "ZEKAPK1\0" as uint64
const uint64_t RAW_PK_MAGIC = 0x5A454B5241504B31ULL;
const uint32_t RAW_PK_VERSION = 1;

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
    uint64_t field_element_size;

    // Constraint system info
    uint64_t cs_num_constraints;
    uint64_t cs_num_variables;
    uint64_t cs_primary_input_size;
    uint64_t cs_auxiliary_input_size;
};

// ============================================================================
// Raw Binary Save Functions
// ============================================================================

/*
 * Write a vector of points as raw binary
 */
template <typename GroupT>
bool write_raw_points(FILE *f, const vector<GroupT> &points)
{
    if (points.empty())
    {
        return true;
    }
    size_t written = fwrite(points.data(), sizeof(GroupT), points.size(), f);
    return written == points.size();
}

/*
 * Write a single point as raw binary
 */
template <typename GroupT>
bool write_raw_point(FILE *f, const GroupT &point)
{
    return fwrite(&point, sizeof(GroupT), 1, f) == 1;
}

/*
 * Save proving key in raw binary format - FAST LOADING!
 *
 * This format stores the exact memory representation of the proving key,
 * allowing it to be loaded with simple fread() calls instead of expensive
 * parsing and point decompression (Tonelli-Shanks sqrt).
 *
 * WARNING: This format is NOT portable across:
 *   - Different architectures (endianness)
 *   - Different compilers (struct padding)
 *   - Different libff builds (Montgomery form parameters)
 */
bool save_pk_raw(const string &filename,
                 const libsnark::r1cs_gg_ppzksnark_proving_key<ppT> &pk)
{

    FILE *f = fopen(filename.c_str(), "wb");
    if (!f)
    {
        cerr << "ERROR: Could not open file for writing: " << filename << endl;
        return false;
    }

    cout << "  Preparing raw PK header..." << endl;

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
    header.field_element_size = sizeof(FieldT);

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
    cout << "    G1 point size: " << sizeof(G1) << " bytes" << endl;
    cout << "    G2 point size: " << sizeof(G2) << " bytes" << endl;
    cout << "    Field element size: " << sizeof(FieldT) << " bytes" << endl;

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
    // (This is small compared to the queries, so standard format is fine)
    cout << "  Writing constraint system..." << endl;

    // We'll use a temp file for the constraint system since it uses stream operators
    string cs_temp = filename + ".cs_temp";
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

    cout << "  Total raw PK size: " << (file_size / 1024 / 1024) << " MB" << endl;

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv)
{
    // Validate arguments first, before any initialization
    if (argc < 3)
    {
        cout << "Usage: " << argv[0] << " [gg] <circuit_file> <output_dir> [--no-standard]" << endl;
        cout << "  circuit_file: Path to the circuit description file" << endl;
        cout << "  output_dir: Directory to save generated keys" << endl;
        cout << "  gg: Optional flag to use generic group model (ppzkSNARK [Gro16])" << endl;
        cout << "  --no-standard: Skip saving standard format PK (only save raw)" << endl;
        cout << endl;
        cout << "Output files:" << endl;
        cout << "  proving_key_raw.bin  - Raw binary format (fast loading,)" << endl;
        cout << "  proving_key.bin      - Standard format (portable, slower loading)" << endl;
        cout << "  verification_key.bin - Verification key (standard format)" << endl;
        return -1;
    }

    try
    {
        auto start_time = steady_clock::now();
        time_t start_wall = time(nullptr);
        cout << "Starting keygen at: " << ctime(&start_wall);

        libff::start_profiling();
        libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
        gadgetlib2::initPublicParamsFromDefaultPp();
        gadgetlib2::GadgetLibAdapter::resetVariableIndex();
        ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

        int inputStartIndex = 0;
        bool useGG = false;
        bool saveStandard = true;

        // Parse arguments
        for (int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "gg") == 0)
            {
                useGG = true;
                inputStartIndex = 1;
            }
            if (strcmp(argv[i], "--no-standard") == 0)
            {
                saveStandard = false;
            }
        }

        if (useGG)
        {
            cout << "Using ppzsknark in the generic group model [Gro16]." << endl;
        }

        string output_dir = argv[2 + inputStartIndex];
        if (output_dir.back() != '/')
        {
            output_dir += '/';
        }

        // Read the circuit - keygen only needs the circuit file, not input values
        CircuitReader reader(argv[1 + inputStartIndex], pb, true);
        r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);

        cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
        cs.auxiliary_input_size = cs.num_variables() - cs.num_inputs();

        cout << "Constraint system created successfully." << endl;
        cout << "  Primary inputs: " << cs.num_inputs() << endl;
        cout << "  Auxiliary inputs: " << cs.auxiliary_input_size << endl;
        cout << "  Constraints: " << cs.num_constraints() << endl;

        if (!cs.is_valid())
        {
            cout << "ERROR: Constraint system is not valid!" << endl;
            return 1;
        }

        // Run only the keygen stage
        cout << endl
             << "Starting keygen..." << endl;
        libff::print_header("R1CS ppzkSNARK Generator");

        auto keygen_start = steady_clock::now();

        r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair =
            libsnark::r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);

        auto keygen_end = steady_clock::now();
        auto keygen_duration = duration_cast<seconds>(keygen_end - keygen_start);

        printf("\n");
        libff::print_indent();
        libff::print_mem("after generator");

        cout << "Keygen completed in " << keygen_duration.count() << " seconds." << endl;

        // Save keys to files
        cout << endl
             << "Saving keys to disk..." << endl;

        try
        {
            // ================================================================
            // Save proving key in RAW BINARY format (fast loading)
            // ================================================================
            cout << endl
                 << "Saving proving key (raw binary format)..." << endl;
            auto raw_start = steady_clock::now();

            string pk_raw_file = output_dir + "proving_key_raw.bin";
            if (!save_pk_raw(pk_raw_file, keypair.pk))
            {
                cout << "Error: Failed to save raw proving key." << endl;
                return -1;
            }

            auto raw_end = steady_clock::now();
            auto raw_duration = duration_cast<milliseconds>(raw_end - raw_start);
            cout << "Raw proving key saved to: " << pk_raw_file << endl;
            cout << "  Save time: " << raw_duration.count() << " ms" << endl;

            // ================================================================
            // Save proving key in STANDARD format (portable, optional)
            // ================================================================
            if (saveStandard)
            {
                cout << endl
                     << "Saving proving key (standard format)..." << endl;
                auto std_start = steady_clock::now();

                string pk_file = output_dir + "proving_key.bin";
                ofstream pk_stream(pk_file, ios::binary);
                if (!pk_stream)
                {
                    cout << "Error: Could not open file " << pk_file << " for writing." << endl;
                    return -1;
                }
                pk_stream << keypair.pk;
                pk_stream.close();

                auto std_end = steady_clock::now();
                auto std_duration = duration_cast<milliseconds>(std_end - std_start);
                cout << "Standard proving key saved to: " << pk_file << endl;
                cout << "  Save time: " << std_duration.count() << " ms" << endl;
            }
            else
            {
                cout << endl
                     << "Skipping standard format PK (--no-standard specified)." << endl;
            }

            // ================================================================
            // Save verification key (always standard format, it's small)
            // ================================================================
            cout << endl
                 << "Saving verification key..." << endl;
            string vk_file = output_dir + "verification_key.bin";
            ofstream vk_stream(vk_file, ios::binary);
            if (!vk_stream)
            {
                cout << "Error: Could not open file " << vk_file << " for writing." << endl;
                return -1;
            }
            vk_stream << keypair.vk;
            vk_stream.close();
            cout << "Verification key saved to: " << vk_file << endl;
        }
        catch (const exception &e)
        {
            cout << "Error while saving keys: " << e.what() << endl;
            return -1;
        }

        auto end_time = steady_clock::now();
        time_t end_wall = time(nullptr);
        auto duration = duration_cast<seconds>(end_time - start_time);

        cout << endl;
        cout << "========================================" << endl;
        cout << "Keygen completed successfully!" << endl;
        cout << "========================================" << endl;
        cout << "Ended at: " << ctime(&end_wall);
        cout << "Total time: " << duration.count() << " seconds ("
             << duration.count() / 60 << " minutes, "
             << duration.count() % 60 << " seconds)" << endl;
        cout << endl;
        cout << "Output files:" << endl;
        cout << "  " << output_dir << "proving_key_raw.bin   (use with run_prover_raw)" << endl;
        if (saveStandard)
        {
            cout << "  " << output_dir << "proving_key.bin       (use with run_prover)" << endl;
        }
        cout << "  " << output_dir << "verification_key.bin" << endl;

        return 0;
    }
    catch (const exception &e)
    {
        cout << "EXCEPTION: " << e.what() << endl;
        return -1;
    }
    catch (...)
    {
        cout << "UNKNOWN EXCEPTION occurred" << endl;
        return -1;
    }
}