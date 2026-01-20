/*
 * run_prover_only.cpp
 *
 * Standalone prover for ZEKRA circuit
 * Loads circuit, inputs, and proving key to generate a zkSNARK proof
 *
 * Usage:
 *   ./run_prover_only [gg] <circuit.arith> <inputs.in> <proving_key.bin> <output_dir>
 *
 * Example:
 *   ./run_prover_only gg zekra.arith zekra_Sample_Run1.in ./keys/proving_key.bin ./output/
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

using namespace std;
using namespace chrono;

int main(int argc, char **argv)
{
    // Validate arguments
    if (argc < 5)
    {
        cout << "Usage: " << argv[0] << " [gg] <circuit.arith> <inputs.in> <proving_key.bin> <output_dir>" << endl;
        cout << endl;
        cout << "  circuit.arith:    Path to the circuit description file" << endl;
        cout << "  inputs.in:        Path to the formatted inputs file" << endl;
        cout << "  proving_key.bin:  Path to the proving key file" << endl;
        cout << "  output_dir:       Directory to save the generated proof" << endl;
        cout << "  gg:               Optional flag to use generic group model (ppzkSNARK [Gro16])" << endl;
        return -1;
    }

    try
    {
        auto start_time = steady_clock::now();
        time_t start_wall = time(nullptr);
        cout << "Starting proof generation at: " << ctime(&start_wall);

        // Initialize libsnark
        libff::start_profiling();
        libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
        gadgetlib2::initPublicParamsFromDefaultPp();
        gadgetlib2::GadgetLibAdapter::resetVariableIndex();
        ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

        // Parse arguments
        int inputStartIndex = 1;
        if (argc == 6)
        {
            if (strcmp(argv[1], "gg") != 0)
            {
                cout << "Invalid Argument - Expected 'gg' flag. Terminating.." << endl;
                return -1;
            }
            else
            {
                cout << "Using ppzkSNARK in the generic group model [Gro16]." << endl;
            }
            inputStartIndex = 1;
        }

        char *circuit_file = argv[1 + inputStartIndex];
        char *input_file = argv[2 + inputStartIndex];
        string pk_file = argv[3 + inputStartIndex];
        string output_dir = argv[4 + inputStartIndex];

        if (output_dir.back() != '/')
        {
            output_dir += '/';
        }

        cout << endl;
        cout << "Circuit file:    " << circuit_file << endl;
        cout << "Input file:      " << input_file << endl;
        cout << "Proving key:     " << pk_file << endl;
        cout << "Output dir:      " << output_dir << endl;
        cout << endl;

        // ============================================================
        // Step 1: Read circuit and inputs
        // ============================================================
        cout << "Loading circuit and inputs..." << endl;

        CircuitReader reader(circuit_file, input_file, pb);

        r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
        const r1cs_variable_assignment<FieldT> full_assignment =
            get_variable_assignment_from_gadgetlib2(*pb);

        cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
        cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

        cout << "  Primary inputs:   " << cs.num_inputs() << endl;
        cout << "  Auxiliary inputs: " << cs.auxiliary_input_size << endl;
        cout << "  Constraints:      " << cs.num_constraints() << endl;

        // Extract primary and auxiliary inputs
        const r1cs_primary_input<FieldT> primary_input(
            full_assignment.begin(),
            full_assignment.begin() + cs.num_inputs());
        const r1cs_auxiliary_input<FieldT> auxiliary_input(
            full_assignment.begin() + cs.num_inputs(),
            full_assignment.end());

        // Verify constraint satisfaction before proving
        cout << endl
             << "Verifying constraint satisfaction..." << endl;
        if (!cs.is_satisfied(primary_input, auxiliary_input))
        {
            cout << "ERROR: The constraint system is NOT satisfied by the provided inputs!" << endl;
            cout << "       The proof would be rejected by the verifier." << endl;
            return -1;
        }
        cout << "  Constraints satisfied: YES" << endl;

        // ============================================================
        // Step 2: Load proving key
        // ============================================================
        cout << endl
             << "Loading proving key from: " << pk_file << endl;

        r1cs_gg_ppzksnark_proving_key<libsnark::default_r1cs_gg_ppzksnark_pp> pk;

        ifstream pk_stream(pk_file, ios::binary);
        if (!pk_stream.good())
        {
            cout << "ERROR: Could not open proving key file: " << pk_file << endl;
            return -1;
        }
        pk_stream >> pk;
        pk_stream.close();

        cout << "  Proving key loaded successfully." << endl;

        // ============================================================
        // Step 3: Generate proof
        // ============================================================
        cout << endl;
        libff::print_header("R1CS GG-ppzkSNARK Prover");

        auto prove_start = steady_clock::now();

        r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof =
            libsnark::r1cs_gg_ppzksnark_prover<libsnark::default_r1cs_gg_ppzksnark_pp>(
                pk, primary_input, auxiliary_input);

        auto prove_end = steady_clock::now();
        auto prove_duration = duration_cast<milliseconds>(prove_end - prove_start);

        printf("\n");
        libff::print_indent();
        libff::print_mem("after prover");

        cout << endl
             << "Proof generation time: " << prove_duration.count() << " ms" << endl;

        // ============================================================
        // Step 4: Save proof and public inputs
        // ============================================================
        cout << endl
             << "Saving proof and public inputs..." << endl;

        // Save proof
        string proof_file = output_dir + "proof.bin";
        ofstream proof_stream(proof_file, ios::binary);
        if (!proof_stream.good())
        {
            cout << "ERROR: Could not open proof file for writing: " << proof_file << endl;
            return -1;
        }
        proof_stream << proof;
        proof_stream.close();
        cout << "  Proof saved to: " << proof_file << endl;

        // Save primary inputs (needed for verification)
        string pi_file = output_dir + "primary_input.bin";
        ofstream pi_stream(pi_file, ios::binary);
        if (!pi_stream.good())
        {
            cout << "ERROR: Could not open primary input file for writing: " << pi_file << endl;
            return -1;
        }
        pi_stream << primary_input;
        pi_stream.close();
        cout << "  Primary inputs saved to: " << pi_file << endl;

        // ============================================================
        // Summary
        // ============================================================
        auto end_time = steady_clock::now();
        time_t end_wall = time(nullptr);
        auto total_duration = duration_cast<seconds>(end_time - start_time);

        cout << endl
             << "========================================" << endl;
        cout << "Proof generation completed successfully!" << endl;
        cout << "========================================" << endl;
        cout << "Ended at: " << ctime(&end_wall);
        cout << "Total time: " << total_duration.count() << " seconds" << endl;
        cout << endl;
        cout << "Output files:" << endl;
        cout << "  - " << proof_file << endl;
        cout << "  - " << pi_file << endl;

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