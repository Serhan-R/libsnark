/*
 * run_setup_serializer.cpp
 *
 * ONE-TIME setup tool that pre-computes and serializes:
 * 1. The constraint system (R1CS matrices)
 * 2. Circuit metadata (variable mappings, wire IDs, etc.)
 *
 * Run this ONCE on your development PC after keygen.
 * The serialized files are then copied to Jetson for fast proving.
 *
 * NO INPUTS FILE NEEDED - the variable mapping depends only on
 * circuit structure, not on specific input values.
 *
 * Usage:
 *   ./run_setup_serializer <circuit.arith> <output_dir>
 *
 * Outputs:
 *   - <output_dir>/constraint_system.bin  (serialized R1CS)
 *   - <output_dir>/circuit_metadata.bin   (variable mappings)
 */

#include "CircuitReader.hpp"
#include "FastWitnessEvaluator.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sys/stat.h>

using namespace std;
using namespace chrono;
using namespace libsnark;
using namespace gadgetlib2;

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        cout << "Usage: " << argv[0] << " <circuit.arith> <output_dir>" << endl;
        cout << endl;
        cout << "This tool pre-serializes the constraint system and circuit metadata" << endl;
        cout << "for use with the optimized prover. Run this ONCE on your PC." << endl;
        cout << endl;
        cout << "NO inputs file is needed - the variable mapping depends only on" << endl;
        cout << "circuit structure, not on specific input values." << endl;
        cout << endl;
        cout << "Outputs:" << endl;
        cout << "  - <output_dir>/constraint_system.bin" << endl;
        cout << "  - <output_dir>/circuit_metadata.bin" << endl;
        return -1;
    }

    try
    {
        auto start_time = steady_clock::now();
        time_t start_wall = time(nullptr);
        cout << "========================================" << endl;
        cout << "ZEKRA Setup Serializer" << endl;
        cout << "========================================" << endl;
        cout << "Started at: " << ctime(&start_wall);

        char *circuit_file = argv[1];
        string output_dir = argv[2];

        if (output_dir.back() != '/')
        {
            output_dir += '/';
        }

        // Create output directory if it doesn't exist
        mkdir(output_dir.c_str(), 0755);

        cout << endl;
        cout << "Circuit file: " << circuit_file << endl;
        cout << "Output dir:   " << output_dir << endl;
        cout << endl;

        // Initialize libsnark
        libff::start_profiling();
        default_r1cs_gg_ppzksnark_pp::init_public_params();
        initPublicParamsFromDefaultPp();
        GadgetLibAdapter::resetVariableIndex();
        ProtoboardPtr pb = Protoboard::create(R1P);

        // Build constraint system using keyGenMode
        // keyGenMode=true means:
        // - parseCircuit() - parses structure only
        // - constructCircuit() - builds constraints AND variableMap
        // - NO mapValuesToProtoboard() - no values needed!
        //
        // The variableMap is built deterministically from circuit structure.

        cout << "Building constraint system (keyGenMode)..." << endl;
        cout << "(This is the slow part - but it only runs ONCE)" << endl;
        cout << endl;

        libff::enter_block("Build constraint system");
        auto cs_start = steady_clock::now();

        // Use keyGenMode constructor - NO inputs file needed!
        CircuitReader reader(circuit_file, pb, true);

        auto cs_mid = steady_clock::now();
        auto parse_duration = duration_cast<milliseconds>(cs_mid - cs_start);
        cout << "  Circuit parsing + constraint building: " << parse_duration.count() << " ms" << endl;

        // Extract constraint system from protoboard
        libff::enter_block("Extract constraint system");
        r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
        libff::leave_block("Extract constraint system");

        auto cs_end = steady_clock::now();
        auto extract_duration = duration_cast<milliseconds>(cs_end - cs_mid);
        cout << "  CS extraction: " << extract_duration.count() << " ms" << endl;

        // Set primary/auxiliary input sizes
        cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
        cs.auxiliary_input_size = cs.num_variables() - cs.num_inputs();

        libff::leave_block("Build constraint system");

        cout << endl;
        cout << "Constraint System Statistics:" << endl;
        cout << "  Total variables:    " << cs.num_variables() << endl;
        cout << "  Primary inputs:     " << cs.num_inputs() << endl;
        cout << "  Auxiliary inputs:   " << cs.auxiliary_input_size << endl;
        cout << "  Constraints:        " << cs.num_constraints() << endl;
        cout << "  NumInputs:          " << reader.getNumInputs() << endl;
        cout << "  NumOutputs:         " << reader.getNumOutputs() << endl;
        cout << "  NumNizkInputs:      " << reader.getNumNizkInputs() << endl;

        if (!cs.is_valid())
        {
            cout << "ERROR: Constraint system is not valid!" << endl;
            return -1;
        }

        // Extract metadata DIRECTLY from CircuitReader
        cout << endl;
        cout << "Extracting circuit metadata from CircuitReader..." << endl;

        libff::enter_block("Build metadata");

        CircuitMetadata metadata;
        metadata.numWires = reader.getNumWires();
        metadata.numInputs = reader.getNumInputs();
        metadata.numOutputs = reader.getNumOutputs();
        metadata.numNizkInputs = reader.getNumNizkInputs();
        metadata.numVariables = cs.num_variables();

        // Get wire IDs directly from CircuitReader
        metadata.inputWireIds = reader.getInputWireIds();
        metadata.outputWireIds = reader.getOutputWireIds();
        metadata.nizkWireIds = reader.getNizkWireIds();

        // Get the variable mapping DIRECTLY from CircuitReader
        // This is built during constructCircuit() 
        metadata.variableMap = reader.variableMap;
        metadata.zeropMap = reader.zeropMap;
        // For zerop gates, record which input wire each one uses
        // (needed to compute the auxiliary inverse value at proof time)
        {
            ifstream arithfs(circuit_file);
            string line;
            getline(arithfs, line); // Skip header

            char type[200];
            char inputStr[8192];
            char outputStr[8192];
            unsigned int numGateInputs, numGateOutputs;

            while (getline(arithfs, line))
            {
                if (line.empty() || line[0] == '#')
                    continue;

                if (5 == sscanf(line.c_str(), "%s in %u <%[^>]> out %u <%[^>]>",
                                type, &numGateInputs, inputStr, &numGateOutputs, outputStr))
                {

                    if (strcmp(type, "zerop") == 0)
                    {
                        // Parse input wire
                        istringstream iss_i(inputStr);
                        Wire inWireId;
                        iss_i >> inWireId;

                        // Parse output wires (second one is the result wire)
                        istringstream iss_o(outputStr);
                        Wire outWire0, outWire1;
                        iss_o >> outWire0 >> outWire1;

                        metadata.zeropInputWires.push_back(make_pair(outWire1, inWireId));
                    }
                }
            }
            arithfs.close();
        }

        libff::leave_block("Build metadata");

        cout << "  Wires:             " << metadata.numWires << endl;
        cout << "  Input wires:       " << metadata.inputWireIds.size() << endl;
        cout << "  Output wires:      " << metadata.outputWireIds.size() << endl;
        cout << "  NIZK wires:        " << metadata.nizkWireIds.size() << endl;
        cout << "  Variable mappings: " << metadata.variableMap.size() << endl;
        cout << "  Zerop mappings:    " << metadata.zeropMap.size() << endl;
        cout << "  Zerop input wires: " << metadata.zeropInputWires.size() << endl;

        // Serialize constraint system
        cout << endl;
        cout << "Serializing constraint system..." << endl;

        libff::enter_block("Serialize constraint system");

        string cs_path = output_dir + "constraint_system.bin";
        ofstream cs_ofs(cs_path, ios::binary);
        if (!cs_ofs.good())
        {
            cout << "ERROR: Could not open file for writing: " << cs_path << endl;
            return -1;
        }
        cs_ofs << cs;
        cs_ofs.close();

        libff::leave_block("Serialize constraint system");

        // Get file size
        ifstream cs_check(cs_path, ios::binary | ios::ate);
        size_t cs_size = cs_check.tellg();
        cs_check.close();
        cout << "  Saved: " << cs_path << " (" << (cs_size / (1024 * 1024)) << " MB)" << endl;

        // Serialize circuit metadata
        cout << endl;
        cout << "Serializing circuit metadata..." << endl;

        libff::enter_block("Serialize metadata");

        string meta_path = output_dir + "circuit_metadata.bin";
        ofstream meta_ofs(meta_path, ios::binary);
        if (!meta_ofs.good())
        {
            cout << "ERROR: Could not open file for writing: " << meta_path << endl;
            return -1;
        }
        metadata.serialize(meta_ofs);
        meta_ofs.close();

        libff::leave_block("Serialize metadata");

        ifstream meta_check(meta_path, ios::binary | ios::ate);
        size_t meta_size = meta_check.tellg();
        meta_check.close();
        cout << "  Saved: " << meta_path << " (" << (meta_size / 1024) << " KB)" << endl;

        // Summary
        auto end_time = steady_clock::now();
        time_t end_wall = time(nullptr);
        auto total_duration = duration_cast<seconds>(end_time - start_time);

        cout << endl;
        cout << "========================================" << endl;
        cout << "Setup serialization completed!" << endl;
        cout << "========================================" << endl;
        cout << "Ended at: " << ctime(&end_wall);
        cout << "Total time: " << total_duration.count() << " seconds" << endl;
        cout << endl;
        cout << "Generated files:" << endl;
        cout << "  1. " << cs_path << endl;
        cout << "  2. " << meta_path << endl;
        cout << endl;
        cout << "Copy these files to Jetson along with proving_key.bin" << endl;
        cout << "Then use run_prover_optimized for fast proving." << endl;

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