/*
 * run_verifier_only.cpp
 *
 * Standalone verifier for ZEKRA circuit
 * Loads verification key, public inputs, and proof to verify
 *
 * Usage:
 *   ./run_verifier_only [gg] <verification_key.bin> <primary_input.bin> <proof.bin>
 *
 * Example:
 *   ./run_verifier_only gg ./keys/verification_key.bin ./output/primary_input.bin ./output/proof.bin
 */

#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <iostream>
#include <fstream>
#include <cstring>
#include <chrono>

using namespace std;
using namespace chrono;

int main(int argc, char **argv)
{
    // Validate arguments
    if (argc < 4)
    {
        cout << "Usage: " << argv[0] << " [gg] <verification_key.bin> <primary_input.bin> <proof.bin>" << endl;
        cout << endl;
        cout << "  verification_key.bin:  Path to the verification key file" << endl;
        cout << "  primary_input.bin:     Path to the primary (public) inputs file" << endl;
        cout << "  proof.bin:             Path to the proof file" << endl;
        cout << "  gg:                    Optional flag to use generic group model (ppzkSNARK [Gro16])" << endl;
        return -1;
    }

    try
    {
        auto start_time = steady_clock::now();
        time_t start_wall = time(nullptr);
        cout << "Starting verification at: " << ctime(&start_wall);

        // Initialize libsnark
        libff::start_profiling();
        libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
        gadgetlib2::initPublicParamsFromDefaultPp();

        // Parse arguments
        int inputStartIndex = 0;
        if (argc == 5)
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

        string vk_file = argv[1 + inputStartIndex];
        string pi_file = argv[2 + inputStartIndex];
        string proof_file = argv[3 + inputStartIndex];

        cout << endl;
        cout << "Verification key:  " << vk_file << endl;
        cout << "Primary inputs:    " << pi_file << endl;
        cout << "Proof:             " << proof_file << endl;
        cout << endl;

        // ============================================================
        // Step 1: Load verification key
        // ============================================================
        cout << "Loading verification key..." << endl;

        libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> vk;

        ifstream vk_stream(vk_file, ios::binary);
        if (!vk_stream.good())
        {
            cout << "ERROR: Could not open verification key file: " << vk_file << endl;
            return -1;
        }
        vk_stream >> vk;
        vk_stream.close();
        cout << "  Verification key loaded." << endl;

        // ============================================================
        // Step 2: Load primary inputs
        // ============================================================
        cout << "Loading primary inputs..." << endl;
        
        libsnark::r1cs_primary_input<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> primary_input;
        
        ifstream pi_stream(pi_file, ios::binary);
        if (!pi_stream.good())
        {
            cout << "ERROR: Could not open primary input file: " << pi_file << endl;
            return -1;
        }
        pi_stream >> primary_input;
        pi_stream.close();
        cout << "  Primary inputs loaded (" << primary_input.size() << " elements)." << endl;

        // ============================================================
        // Step 3: Load proof
        // ============================================================
        cout << "Loading proof..." << endl;
        
        libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof;
        
        ifstream proof_stream(proof_file, ios::binary);
        if (!proof_stream.good())
        {
            cout << "ERROR: Could not open proof file: " << proof_file << endl;
            return -1;
        }
        proof_stream >> proof;
        proof_stream.close();
        cout << "  Proof loaded." << endl;

        // ============================================================
        // Step 4: Verify proof
        // ============================================================
        cout << endl;
        libff::print_header("R1CS GG-ppzkSNARK Verifier");

        auto verify_start = steady_clock::now();

        bool verified = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_gg_ppzksnark_pp>(
            vk, primary_input, proof);

        auto verify_end = steady_clock::now();
        auto verify_duration = duration_cast<milliseconds>(verify_end - verify_start);

        printf("\n");
        libff::print_indent();
        libff::print_mem("after verifier");

        // ============================================================
        // Result
        // ============================================================
        auto end_time = steady_clock::now();
        time_t end_wall = time(nullptr);
        auto total_duration = duration_cast<milliseconds>(end_time - start_time);

        cout << endl << "========================================" << endl;
        if (verified)
        {
            cout << "VERIFICATION RESULT: *** ACCEPTED ***" << endl;
            cout << "The proof is VALID." << endl;
        }
        else
        {
            cout << "VERIFICATION RESULT: *** REJECTED ***" << endl;
            cout << "The proof is INVALID!" << endl;
        }
        cout << "========================================" << endl;
        cout << "Verification time: " << verify_duration.count() << " ms" << endl;
        cout << "Total time: " << total_duration.count() << " ms" << endl;
        cout << "Ended at: " << ctime(&end_wall);

        return verified ? 0 : 1;
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
