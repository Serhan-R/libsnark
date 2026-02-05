/*
 * run_prover_interactive.cpp
 *
 * INTERACTIVE MODE prover that keeps proving key in memory between proofs.
 * 
 *
 * Usage:
 *   ./run_prover_interactive <circuit.arith> <proving_key.bin> \
 *                       <constraint_system.bin> <circuit_metadata.bin> <output_dir>
 *
 * Then enter input file paths interactively, one per line.
 * Type 'quit' or 'exit' to stop.
 */

#include "CircuitReader.hpp"
#include "FastWitnessEvaluator.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <streambuf>
#include <sstream>
#include <sys/stat.h>

using namespace std;
using namespace chrono;
using namespace libsnark;

typedef default_r1cs_gg_ppzksnark_pp ppT;

// Global state - persists between proofs!
static r1cs_gg_ppzksnark_proving_key<ppT> *g_pk = nullptr;
static r1cs_constraint_system<FieldT> *g_cs = nullptr;
static CircuitMetadata *g_metadata = nullptr;
static string g_circuit_file;
static string g_output_dir;
static bool g_initialized = false;

// Proof counter for unique output filenames
static int g_proof_count = 0;

struct vector_membuf : std::streambuf
{
    vector_membuf(char *begin, char *end)
    {
        this->setg(begin, begin, end);
    }
};

/*
 * Initialize the prover - loads PK, CS, metadata into memory.
 * This is the slow part (~28 seconds) but only happens ONCE.
 */
bool initProver(const string &pk_file, const string &cs_file, const string &meta_file)
{
    if (g_initialized)
    {
        cout << "Prover already initialized." << endl;
        return true;
    }

    try
    {
        cout << endl;
        cout << "========================================" << endl;
        cout << "Initializing Prover (one-time setup)" << endl;
        cout << "========================================" << endl;

        auto init_start = steady_clock::now();

        // Load proving key
        libff::enter_block("Load proving key");
        cout << "Loading proving key..." << endl;

        g_pk = new r1cs_gg_ppzksnark_proving_key<ppT>();

        ifstream pk_ifs(pk_file, ios::binary | ios::ate);
        if (!pk_ifs.good())
        {
            cout << "ERROR: Could not open proving key: " << pk_file << endl;
            return false;
        }

        libff::enter_block("Read PK into RAM");
        streamsize pk_size = pk_ifs.tellg();
        pk_ifs.seekg(0, ios::beg);
        vector<char> pk_buffer(pk_size);
        pk_ifs.read(pk_buffer.data(), pk_size);
        pk_ifs.close();
        libff::leave_block("Read PK into RAM");

        libff::enter_block("Deserialize proving key");
        vector_membuf pk_sbuf(pk_buffer.data(), pk_buffer.data() + pk_buffer.size());
        istream pk_memstream(&pk_sbuf);
        pk_memstream >> *g_pk;
        libff::leave_block("Deserialize proving key");

        auto pk_time = steady_clock::now();
        cout << "  PK loaded in " << duration_cast<milliseconds>(pk_time - init_start).count() << " ms" << endl;
        libff::leave_block("Load proving key");

        // Load constraint system
        libff::enter_block("Load constraint system");
        cout << "Loading constraint system..." << endl;

        g_cs = new r1cs_constraint_system<FieldT>();

        ifstream cs_ifs(cs_file, ios::binary | ios::ate);
        if (!cs_ifs.good())
        {
            cout << "ERROR: Could not open constraint system: " << cs_file << endl;
            return false;
        }

        libff::enter_block("Read CS into RAM");
        streamsize cs_size = cs_ifs.tellg();
        cs_ifs.seekg(0, ios::beg);
        vector<char> cs_buffer(cs_size);
        cs_ifs.read(cs_buffer.data(), cs_size);
        cs_ifs.close();
        libff::leave_block("Read CS into RAM");

        libff::enter_block("Deserialize constraint system");
        vector_membuf cs_sbuf(cs_buffer.data(), cs_buffer.data() + cs_buffer.size());
        istream cs_memstream(&cs_sbuf);
        cs_memstream >> *g_cs;
        libff::leave_block("Deserialize constraint system");

        auto cs_time = steady_clock::now();
        cout << "  CS loaded in " << duration_cast<milliseconds>(cs_time - pk_time).count() << " ms" << endl;
        cout << "  Constraints: " << g_cs->num_constraints() << endl;
        cout << "  Variables: " << g_cs->num_variables() << endl;
        libff::leave_block("Load constraint system");

        // Load circuit metadata
        libff::enter_block("Load circuit metadata");
        cout << "Loading circuit metadata..." << endl;

        g_metadata = new CircuitMetadata();
        ifstream meta_ifs(meta_file, ios::binary);
        if (!meta_ifs.good())
        {
            cout << "ERROR: Could not open metadata: " << meta_file << endl;
            return false;
        }
        g_metadata->deserialize(meta_ifs);
        meta_ifs.close();

        auto meta_time = steady_clock::now();
        cout << "  Metadata loaded in " << duration_cast<milliseconds>(meta_time - cs_time).count() << " ms" << endl;
        libff::leave_block("Load circuit metadata");

        auto init_end = steady_clock::now();
        cout << endl;
        cout << "========================================" << endl;
        cout << "Prover ready! Initialization took "
             << duration_cast<milliseconds>(init_end - init_start).count() << " ms" << endl;
        cout << "========================================" << endl;
        cout << endl;

        g_initialized = true;
        return true;
    }
    catch (const exception &e)
    {
        cout << "ERROR during initialization: " << e.what() << endl;
        return false;
    }
}

/*
 * Generate a single proof - this is now FAST because PK is already loaded!
 */
int generateProof(const char *input_file)
{
    if (!g_initialized)
    {
        cout << "ERROR: Prover not initialized!" << endl;
        return -1;
    }

    g_proof_count++;
    auto total_start = steady_clock::now();

    cout << endl;
    cout << "--- Proof #" << g_proof_count << " ---" << endl;
    cout << "Input: " << input_file << endl;

    // Step 1: Fast witness evaluation
    libff::enter_block("Fast witness evaluation");
    FastWitnessEvaluator evaluator;
    evaluator.evaluate(g_circuit_file.c_str(), input_file);
    libff::leave_block("Fast witness evaluation");

    // Step 2: Build variable assignment
    libff::enter_block("Build variable assignment");
    vector<FieldT> fullAssignment;
    size_t expectedSize = g_cs->num_variables();
    evaluator.buildAssignment(*g_metadata, fullAssignment, expectedSize);
    libff::leave_block("Build variable assignment");

    // Step 3: Extract primary and auxiliary inputs
    size_t num_primary = g_cs->num_inputs();

    if (fullAssignment.size() < num_primary)
    {
        cout << "ERROR: Assignment too small!" << endl;
        return -1;
    }

    r1cs_primary_input<FieldT> primary_input(
        fullAssignment.begin(),
        fullAssignment.begin() + num_primary);

    r1cs_auxiliary_input<FieldT> auxiliary_input(
        fullAssignment.begin() + num_primary,
        fullAssignment.end());

    // Step 4: Verify constraints (optional - can skip for speed)
    libff::enter_block("Verify constraints");
    if (!g_cs->is_satisfied(primary_input, auxiliary_input))
    {
        cout << "ERROR: Constraints NOT satisfied!" << endl;
        libff::leave_block("Verify constraints");
        return -1;
    }
    libff::leave_block("Verify constraints");

    // Step 5: Generate proof
    libff::enter_block("Generate proof");
    auto prove_start = steady_clock::now();

    r1cs_gg_ppzksnark_proof<ppT> proof =
        r1cs_gg_ppzksnark_prover<ppT>(*g_pk, primary_input, auxiliary_input);

    auto prove_end = steady_clock::now();
    libff::leave_block("Generate proof");

    // Step 6: Save outputs
    stringstream proof_filename;
    proof_filename << g_output_dir << "proof_" << g_proof_count << ".bin";
    ofstream proof_ofs(proof_filename.str(), ios::binary);
    proof_ofs << proof;
    proof_ofs.close();

    stringstream pi_filename;
    pi_filename << g_output_dir << "primary_input_" << g_proof_count << ".bin";
    ofstream pi_ofs(pi_filename.str(), ios::binary);
    pi_ofs << primary_input;
    pi_ofs.close();

    auto total_end = steady_clock::now();

    cout << "Proof generated in " << duration_cast<milliseconds>(total_end - total_start).count() << " ms" << endl;
    cout << "  Crypto time: " << duration_cast<milliseconds>(prove_end - prove_start).count() << " ms" << endl;
    cout << "  Output: " << proof_filename.str() << endl;

    return 0;
}

void printUsage(const char *progname)
{
    cout << "INTERACTIVE MODE PROVER" << endl;
    cout << "==================" << endl;
    cout << endl;
    cout << "Keeps proving key in memory for fast repeated proofs." << endl;
    cout << endl;
    cout << "Usage: " << progname << " <circuit.arith> <proving_key.bin> \\" << endl;
    cout << "                         <constraint_system.bin> <circuit_metadata.bin> <output_dir>" << endl;
    cout << endl;
    cout << "After initialization, enter input file paths (one per line)." << endl;
    cout << "Type 'quit' or 'exit' to stop." << endl;
    cout << endl;
    cout << "Performance:" << endl;
    cout << "  First proof:  ~35 seconds (includes loading)" << endl;
    cout << "  Next proofs:  ~8 seconds each (PK in memory!)" << endl;
}

int main(int argc, char **argv)
{
    if (argc < 6)
    {
        printUsage(argv[0]);
        return -1;
    }

    try
    {
        // Initialize libsnark
        libff::start_profiling();
        default_r1cs_gg_ppzksnark_pp::init_public_params();

        // Parse arguments
        g_circuit_file = argv[1];
        string pk_file = argv[2];
        string cs_file = argv[3];
        string meta_file = argv[4];
        g_output_dir = argv[5];

        if (g_output_dir.back() != '/')
        {
            g_output_dir += '/';
        }

        // Create output directory
        mkdir(g_output_dir.c_str(), 0755);

        // Initialize prover (load PK, CS, metadata) - SLOW but only once!
        cout << "Starting interactive mode prover..." << endl;
        cout << "This will take ~30 seconds to load keys, then proofs are fast!" << endl;
        cout << endl;

        if (!initProver(pk_file, cs_file, meta_file))
        {
            return -1;
        }

        // Interactive loop - keeps PK in memory!
        cout << "========================================" << endl;
        cout << "READY FOR PROOF REQUESTS" << endl;
        cout << "========================================" << endl;
        cout << "Enter input file path (or 'quit' to exit):" << endl;
        cout << "> ";

        string line;
        while (getline(cin, line))
        {
            // Trim whitespace
            size_t start = line.find_first_not_of(" \t\r\n");
            size_t end = line.find_last_not_of(" \t\r\n");
            if (start == string::npos)
            {
                cout << "> ";
                continue;
            }
            line = line.substr(start, end - start + 1);

            // Check for exit commands
            if (line == "quit" || line == "exit" || line == "q")
            {
                cout << "Shutting down..." << endl;
                break;
            }

            // Check for help
            if (line == "help" || line == "?")
            {
                cout << "Commands:" << endl;
                cout << "  <filepath>  - Generate proof for input file" << endl;
                cout << "  status      - Show prover status" << endl;
                cout << "  quit/exit   - Shutdown interactive mode prover" << endl;
                cout << "> ";
                continue;
            }

            // Check for status
            if (line == "status")
            {
                cout << "Prover status:" << endl;
                cout << "  Initialized: " << (g_initialized ? "YES" : "NO") << endl;
                cout << "  Proofs generated: " << g_proof_count << endl;
                cout << "  Circuit: " << g_circuit_file << endl;
                cout << "  Output dir: " << g_output_dir << endl;
                cout << "> ";
                continue;
            }

            // Check if file exists
            ifstream test(line);
            if (!test.good())
            {
                cout << "ERROR: File not found: " << line << endl;
                cout << "> ";
                continue;
            }
            test.close();

            // Generate proof!
            generateProof(line.c_str());

            cout << "> ";
        }

        // Cleanup
        cout << "Cleaning up..." << endl;
        delete g_pk;
        delete g_cs;
        delete g_metadata;

        cout << "Interactive mode prover stopped. Generated " << g_proof_count << " proofs." << endl;
        return 0;
    }
    catch (const exception &e)
    {
        cout << "EXCEPTION: " << e.what() << endl;
        return -1;
    }
}
