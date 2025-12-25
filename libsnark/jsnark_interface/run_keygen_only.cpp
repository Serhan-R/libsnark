/*
 * run_keygen_only.cpp
 *
 * Modified from run_ppzksnark.cpp to run only the keygen (generator) stage
 * Saves the proving and verification keys to disk for later use
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <fstream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>

int main(int argc, char **argv) {
    cout << "--- Start profil ---" << endl;
    libff::start_profiling();
    cout << "--- default_r1cs_gg_ppzksnark_pp::init_public_params(); ---" << endl;
    libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
    cout << "--- Start initPublicParamsFromDefaultPp ---" << endl;
	gadgetlib2::initPublicParamsFromDefaultPp();
	cout << "--- Initialized successfully ---" << endl;
    cout << "--- Start resetVariableIndex ---" << endl;
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    cout << "--- Start Protoboard creation ---" << endl;
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 0;
    cout << "--- first if ---" << endl;
    if(argc == 4){
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
    cout << "--- setting output dir ---" << endl;
    string output_dir = argv[2 + inputStartIndex];
    if (output_dir.back() != '/')
    {
        output_dir += '/';
    }

    cout << "--- reader ---" << endl;
    // Read the circuit - keygen only needs the circuit structure, not input values
	CircuitReader reader(argv[1 + inputStartIndex], pb, true);
    cout << "--- get_constraint_system_from_gadgetlib2 ---" << endl;
    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
    cout << "--- full assignment ---" << endl;
    const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
    cout << "--- primary input size ---" << endl;
    cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
    cout << "--- auxilary input size ---" << endl;
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

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
	cout << endl << "Starting keygen..." << endl;
	libff::print_header("R1CS ppzkSNARK Generator");

    r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair = libsnark::r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);

	
	printf("\n"); libff::print_indent(); libff::print_mem("after generator");

	// Save keys to files
	cout << endl << "Saving keys to disk..." << endl;
	
	try {
		// Save proving key
		string pk_file = output_dir + "proving_key.bin";
		ofstream pk_stream(pk_file, ios::binary);
		if(!pk_stream) {
			cout << "Error: Could not open file " << pk_file << " for writing." << endl;
			return -1;
		}
		pk_stream << keypair.pk;
		pk_stream.close();
		cout << "Proving key saved to: " << pk_file << endl;
		
		// Save verification key
		string vk_file = output_dir + "verification_key.bin";
		ofstream vk_stream(vk_file, ios::binary);
		if(!vk_stream) {
			cout << "Error: Could not open file " << vk_file << " for writing." << endl;
			return -1;
		}
		vk_stream << keypair.vk;
		vk_stream.close();
		cout << "Verification key saved to: " << vk_file << endl;
		
	} catch (const exception& e) {
		cout << "Error while saving keys: " << e.what() << endl;
		return -1;
	}

	cout << endl << "Keygen completed successfully!" << endl;
	return 0;
}
