/*
 * run_keygen_only.cpp
 *
 * Modified from run_ppzksnark.cpp to run only the keygen (generator) stage
 * Saves the proving and verification keys to disk for later use
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
	// Validate arguments first, before any initialization
	if (argc < 3)
	{
		cout << "Usage: " << argv[0] << " [gg] <circuit_file> <output_dir>" << endl;
		cout << "  circuit_file: Path to the circuit description file" << endl;
		cout << "  output_dir: Directory to save generated keys" << endl;
		cout << "  gg: Optional flag to use generic group model (ppzkSNARK [Gro16])" << endl;
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
		if (argc == 4)
		{
			if (strcmp(argv[1], "gg") != 0)
			{
				cout << "Invalid Argument - Terminating.." << endl;
				return -1;
			}
			else
			{
				cout << "Using ppzsknark in the generic group model [Gro16]." << endl;
			}
			inputStartIndex = 1;
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

		r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair =
			libsnark::r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);

		printf("\n");
		libff::print_indent();
		libff::print_mem("after generator");

		// Save keys to files
		cout << endl
			 << "Saving keys to disk..." << endl;

		try
		{
			// Save proving key
			string pk_file = output_dir + "proving_key.bin";
			ofstream pk_stream(pk_file, ios::binary);
			if (!pk_stream)
			{
				cout << "Error: Could not open file " << pk_file << " for writing." << endl;
				return -1;
			}
			pk_stream << keypair.pk;
			pk_stream.close();
			cout << "Proving key saved to: " << pk_file << endl;

			// Save verification key
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
		
		cout << endl
			 << "Keygen completed successfully!" << endl;
		cout << "Ended at: " << ctime(&end_wall);
		cout << "Total time: " << duration.count() << " seconds (" 
			 << duration.count() / 60 << " minutes, " 
			 << duration.count() % 60 << " seconds)" << endl;
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
