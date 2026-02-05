/*
 * run_prover_optimized.cpp
 *
 * OPTIMIZED prover for ZEKRA that uses pre-serialized constraint system.
 * This eliminates the expensive constraint translation step on every proof.
 *
 *
 * Usage:
 *   ./run_prover_optimized <circuit.arith> <inputs.in> <proving_key.bin> \
 *                          <constraint_system.bin> <circuit_metadata.bin> <output_dir>
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

using namespace std;
using namespace chrono;
using namespace libsnark;

typedef default_r1cs_gg_ppzksnark_pp ppT;

// Global state for daemon mode (keeps PK and CS in memory)
static r1cs_gg_ppzksnark_proving_key<ppT> *g_pk = nullptr;
static r1cs_constraint_system<FieldT> *g_cs = nullptr;
static CircuitMetadata *g_metadata = nullptr;
static bool g_initialized = false;

struct vector_membuf : std::streambuf
{
    vector_membuf(char *begin, char *end)
    {
        this->setg(begin, begin, end);
    }
};

/*
 * Initialize the prover by loading proving key, constraint system, and metadata.
 * Call this ONCE at startup for daemon mode.
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
        cout << "Initializing Optimized Prover" << endl;
        cout << "========================================" << endl;

        auto init_start = steady_clock::now();

        libff::enter_block("Load proving key");
        cout << "Loading proving key..." << endl;

        g_pk = new r1cs_gg_ppzksnark_proving_key<ppT>();

        ifstream pk_ifs(pk_file, ios::binary | ios::ate); 
        if (!pk_ifs.good())
        {
            cout << "ERROR: Could not open proving key: " << pk_file << endl;
            return false;
        }

        // Read the whole file into RAM (Eliminates disk latency)
        libff::enter_block("read PK into RAM");

        streamsize pk_size = pk_ifs.tellg();
        pk_ifs.seekg(0, ios::beg);
        vector<char> pk_buffer(pk_size);
        pk_ifs.read(pk_buffer.data(), pk_size);
        pk_ifs.close(); // Close disk connection 

        libff::leave_block("read PK into RAM");
        // Stream from RAM

        libff::enter_block("Deserialize proving key from RAM buffer");

        vector_membuf pk_sbuf(pk_buffer.data(), pk_buffer.data() + pk_buffer.size());
        istream pk_memstream(&pk_sbuf);
        pk_memstream >> *g_pk;

        libff::leave_block("Deserialize proving key from RAM buffer");

        auto pk_time = steady_clock::now();
        cout << "  Loaded in " << duration_cast<milliseconds>(pk_time - init_start).count() << " ms" << endl;
        libff::leave_block("Load proving key");

        //  Load constraint system
        libff::enter_block("Load constraint system");
        cout << "Loading constraint system..." << endl;

        g_cs = new r1cs_constraint_system<FieldT>();

        ifstream cs_ifs(cs_file, ios::binary | ios::ate);
        if (!cs_ifs.good())
        {
            cout << "ERROR: Could not open constraint system: " << cs_file << endl;
            return false;
        }

        // Read the whole file into RAM

        libff::enter_block("read CS into RAM");

        streamsize cs_size = cs_ifs.tellg();
        cs_ifs.seekg(0, ios::beg);
        vector<char> cs_buffer(cs_size);
        cs_ifs.read(cs_buffer.data(), cs_size);
        cs_ifs.close();

        libff::leave_block("read CS into RAM");

        // Stream from RAM

        libff::enter_block("Deserialize constraint system from RAM buffer");

        vector_membuf cs_sbuf(cs_buffer.data(), cs_buffer.data() + cs_buffer.size());
        istream cs_memstream(&cs_sbuf);
        cs_memstream >> *g_cs;

        libff::leave_block("Deserialize constraint system from RAM buffer");

        auto cs_time = steady_clock::now();
        cout << "  Loaded in " << duration_cast<milliseconds>(cs_time - pk_time).count() << " ms" << endl;
        cout << "  Constraints: " << g_cs->num_constraints() << endl;
        cout << "  Variables (CS): " << g_cs->num_variables() << endl;
        cout << "  num_inputs(): " << g_cs->num_inputs() << endl;
        cout << "  primary_input_size: " << g_cs->primary_input_size << endl;
        cout << "  auxiliary_input_size: " << g_cs->auxiliary_input_size << endl;
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
        cout << "  Loaded in " << duration_cast<milliseconds>(meta_time - cs_time).count() << " ms" << endl;
        cout << "  numInputs: " << g_metadata->numInputs << endl;
        cout << "  numOutputs: " << g_metadata->numOutputs << endl;
        cout << "  numNizkInputs: " << g_metadata->numNizkInputs << endl;
        cout << "  numVariables (metadata): " << g_metadata->numVariables << endl;
        cout << "  variableMap size: " << g_metadata->variableMap.size() << endl;
        cout << "  zeropMap size: " << g_metadata->zeropMap.size() << endl;
        cout << "  maxVariableIndex: " << g_metadata->getMaxVariableIndex() << endl;
        libff::leave_block("Load circuit metadata");

        auto init_end = steady_clock::now();
        cout << endl;
        cout << "Prover initialized in "
             << duration_cast<milliseconds>(init_end - init_start).count() << " ms" << endl;
        cout << "========================================" << endl;

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
 * Generate a proof using the optimized path.
 * Skips constraint translation entirely by using pre-serialized CS.
 */
int generateProofOptimized(
    const char *circuit_file,
    const char *input_file,
    const string &output_dir)
{
    if (!g_initialized)
    {
        cout << "ERROR: Prover not initialized. Call initProver() first." << endl;
        return -1;
    }

    auto total_start = steady_clock::now();

    cout << endl;
    cout << "========================================" << endl;
    cout << "Generating Proof (Optimized)" << endl;
    cout << "========================================" << endl;
    cout << "Circuit: " << circuit_file << endl;
    cout << "Inputs:  " << input_file << endl;
    cout << endl;

    // Fast witness evaluation 
    libff::enter_block("Fast witness evaluation");

    FastWitnessEvaluator evaluator;
    evaluator.evaluate(circuit_file, input_file);

    libff::leave_block("Fast witness evaluation");

    // Build variable assignment from wire values
    libff::enter_block("Build variable assignment");

    vector<FieldT> fullAssignment;

    // Compute the expected assignment size from the metadata
    // The assignment size should be maxVariableIndex + 1
    // This matches how CircuitReader builds the variableMap
    size_t expectedSize = g_cs->num_variables();

    cout << "  Expected assignment size (from metadata): " << expectedSize << endl;
    cout << "  CS num_variables: " << g_cs->num_variables() << endl;
    cout << "  CS num_inputs: " << g_cs->num_inputs() << endl;

    evaluator.buildAssignment(*g_metadata, fullAssignment, expectedSize);

    libff::leave_block("Build variable assignment");

    // Extract primary and auxiliary inputs
    libff::enter_block("Extract inputs");

    size_t num_primary = g_cs->num_inputs();

    cout << "  Full assignment size: " << fullAssignment.size() << endl;
    cout << "  num_primary (from CS): " << num_primary << endl;

    if (fullAssignment.size() < num_primary)
    {
        cout << "ERROR: Assignment too small! " << fullAssignment.size()
             << " < " << num_primary << endl;
        libff::leave_block("Extract inputs");
        return -1;
    }

    r1cs_primary_input<FieldT> primary_input(
        fullAssignment.begin(),
        fullAssignment.begin() + num_primary);

    r1cs_auxiliary_input<FieldT> auxiliary_input(
        fullAssignment.begin() + num_primary,
        fullAssignment.end());

    cout << "  Primary inputs: " << primary_input.size() << endl;
    cout << "  Auxiliary inputs: " << auxiliary_input.size() << endl;

    libff::leave_block("Extract inputs");

    // Verify constraint satisfaction (optional can be skipped)
    libff::enter_block("Verify constraints");

    cout << "Verifying constraint satisfaction..." << endl;
    if (!g_cs->is_satisfied(primary_input, auxiliary_input))
    {
        cout << "ERROR: Constraints NOT satisfied!" << endl;
        cout << "       The proof would be invalid." << endl;
        cout << endl;
        cout << "Debug info:" << endl;
        cout << "  primary_input.size() = " << primary_input.size() << endl;
        cout << "  auxiliary_input.size() = " << auxiliary_input.size() << endl;
        cout << "  cs.num_inputs() = " << g_cs->num_inputs() << endl;
        cout << "  cs.num_variables() = " << g_cs->num_variables() << endl;
        cout << "  cs.num_constraints() = " << g_cs->num_constraints() << endl;
        cout << "  Expected: primary=" << g_cs->primary_input_size
             << ", auxiliary=" << g_cs->auxiliary_input_size << endl;
        libff::leave_block("Verify constraints");
        return -1;
    }
    cout << "  Constraints satisfied: YES" << endl;

    libff::leave_block("Verify constraints");

    // Generate the actual proof
    cout << endl;
    libff::print_header("R1CS GG-ppzkSNARK Prover");

    auto prove_start = steady_clock::now();

    r1cs_gg_ppzksnark_proof<ppT> proof =
        r1cs_gg_ppzksnark_prover<ppT>(*g_pk, primary_input, auxiliary_input);

    auto prove_end = steady_clock::now();
    auto prove_duration = duration_cast<milliseconds>(prove_end - prove_start);

    cout << endl;
    cout << "Proof generation time: " << prove_duration.count() << " ms" << endl;

    // Save proof and primary inputs
    libff::enter_block("Save outputs");

    // Save proof
    string proof_file = output_dir + "proof.bin";
    ofstream proof_ofs(proof_file, ios::binary);
    if (!proof_ofs.good())
    {
        cout << "ERROR: Could not open proof file: " << proof_file << endl;
        return -1;
    }
    proof_ofs << proof;
    proof_ofs.close();
    cout << "  Proof saved to: " << proof_file << endl;

    // Save primary inputs
    string pi_file = output_dir + "primary_input.bin";
    ofstream pi_ofs(pi_file, ios::binary);
    if (!pi_ofs.good())
    {
        cout << "ERROR: Could not open primary input file: " << pi_file << endl;
        return -1;
    }
    pi_ofs << primary_input;
    pi_ofs.close();
    cout << "  Primary inputs saved to: " << pi_file << endl;

    libff::leave_block("Save outputs");

    // Summary
    auto total_end = steady_clock::now();
    auto total_duration = duration_cast<milliseconds>(total_end - total_start);

    cout << endl;
    cout << "========================================" << endl;
    cout << "Proof generation completed!" << endl;
    cout << "========================================" << endl;
    cout << "Total time: " << total_duration.count() << " ms" << endl;
    cout << endl;
    cout << "Output files:" << endl;
    cout << "  - " << proof_file << endl;
    cout << "  - " << pi_file << endl;

    return 0;
}

void printUsage(const char *progname)
{
    cout << "Usage: " << progname << " <circuit.arith> <inputs.in> <proving_key.bin> \\" << endl;
    cout << "                         <constraint_system.bin> <circuit_metadata.bin> <output_dir>" << endl;
    cout << endl;
    cout << "Arguments:" << endl;
    cout << "  circuit.arith          Path to the circuit description file" << endl;
    cout << "  inputs.in              Path to the formatted inputs file" << endl;
    cout << "  proving_key.bin        Path to the proving key (from keygen)" << endl;
    cout << "  constraint_system.bin  Path to pre-serialized constraint system" << endl;
    cout << "  circuit_metadata.bin   Path to pre-serialized circuit metadata" << endl;
    cout << "  output_dir             Directory to save the generated proof" << endl;
    cout << endl;
    cout << "The constraint_system.bin and circuit_metadata.bin files are generated" << endl;
    cout << "by running run_setup_serializer ONCE on your development PC." << endl;
}

int main(int argc, char **argv)
{
    if (argc < 7)
    {
        printUsage(argv[0]);
        return -1;
    }

    try
    {
        auto start_time = steady_clock::now();
        time_t start_wall = time(nullptr);
        cout << "Starting optimized proof generation at: " << ctime(&start_wall);

        // Initialize libsnark
        libff::start_profiling();
        default_r1cs_gg_ppzksnark_pp::init_public_params();

        // Parse arguments
        char *circuit_file = argv[1];
        char *input_file = argv[2];
        string pk_file = argv[3];
        string cs_file = argv[4];
        string meta_file = argv[5];
        string output_dir = argv[6];

        if (output_dir.back() != '/')
        {
            output_dir += '/';
        }

        // Initialize prover (loads PK, CS, metadata)
        if (!initProver(pk_file, cs_file, meta_file))
        {
            return -1;
        }

        // Generate proof
        int result = generateProofOptimized(circuit_file, input_file, output_dir);

        auto end_time = steady_clock::now();
        time_t end_wall = time(nullptr);
        auto total_duration = duration_cast<seconds>(end_time - start_time);

        cout << endl;
        cout << "Ended at: " << ctime(&end_wall);
        cout << "Total wall time: " << total_duration.count() << " seconds" << endl;

        // Cleanup
        delete g_pk;
        delete g_cs;
        delete g_metadata;

        return result;
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