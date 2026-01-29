/*
 * FastWitnessEvaluator.hpp
 *
 * Lightweight circuit evaluator that ONLY computes wire values.
 * Does NOT build any constraints - used for fast proving when
 * the constraint system has been pre-serialized.   
 */

#ifndef FAST_WITNESS_EVALUATOR_HPP_
#define FAST_WITNESS_EVALUATOR_HPP_

#include "Util.hpp"
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>

#include <iostream>
#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <cstring>
#include <chrono>

typedef unsigned int Wire;
typedef libff::Fr<libff::default_ec_pp> FieldT;
typedef std::map<Wire, unsigned int> WireMap;

/*
 * Serializable metadata about the circuit structure.
 * This is saved once during setup and loaded at runtime
 * to enable fast witness construction without rebuilding constraints.
 */
struct CircuitMetadata
{
    unsigned int numWires;
    unsigned int numInputs;
    unsigned int numNizkInputs;
    unsigned int numOutputs;
    unsigned int numVariables; // Total variables in the constraint system

    std::vector<Wire> inputWireIds;
    std::vector<Wire> outputWireIds;
    std::vector<Wire> nizkWireIds;

    // Maps wire ID -> variable index in the assignment
    WireMap variableMap;

    // For zerop gates: maps output wire -> auxiliary variable index
    WireMap zeropMap;

    // For zerop gates: stores which wire is the input to each zerop
    // (needed to compute the auxiliary inverse value)
    std::vector<std::pair<Wire, Wire>> zeropInputWires; // (outputWire, inputWire)

    void serialize(std::ostream &out) const
    {
        out.write(reinterpret_cast<const char *>(&numWires), sizeof(numWires));
        out.write(reinterpret_cast<const char *>(&numInputs), sizeof(numInputs));
        out.write(reinterpret_cast<const char *>(&numNizkInputs), sizeof(numNizkInputs));
        out.write(reinterpret_cast<const char *>(&numOutputs), sizeof(numOutputs));
        out.write(reinterpret_cast<const char *>(&numVariables), sizeof(numVariables));

        // Serialize vectors
        size_t size;

        size = inputWireIds.size();
        out.write(reinterpret_cast<const char *>(&size), sizeof(size));
        out.write(reinterpret_cast<const char *>(inputWireIds.data()), size * sizeof(Wire));

        size = outputWireIds.size();
        out.write(reinterpret_cast<const char *>(&size), sizeof(size));
        out.write(reinterpret_cast<const char *>(outputWireIds.data()), size * sizeof(Wire));

        size = nizkWireIds.size();
        out.write(reinterpret_cast<const char *>(&size), sizeof(size));
        out.write(reinterpret_cast<const char *>(nizkWireIds.data()), size * sizeof(Wire));

        // Serialize variableMap
        size = variableMap.size();
        out.write(reinterpret_cast<const char *>(&size), sizeof(size));
        for (const auto &kv : variableMap)
        {
            out.write(reinterpret_cast<const char *>(&kv.first), sizeof(kv.first));
            out.write(reinterpret_cast<const char *>(&kv.second), sizeof(kv.second));
        }

        // Serialize zeropMap
        size = zeropMap.size();
        out.write(reinterpret_cast<const char *>(&size), sizeof(size));
        for (const auto &kv : zeropMap)
        {
            out.write(reinterpret_cast<const char *>(&kv.first), sizeof(kv.first));
            out.write(reinterpret_cast<const char *>(&kv.second), sizeof(kv.second));
        }

        // Serialize zeropInputWires
        size = zeropInputWires.size();
        out.write(reinterpret_cast<const char *>(&size), sizeof(size));
        for (const auto &p : zeropInputWires)
        {
            out.write(reinterpret_cast<const char *>(&p.first), sizeof(p.first));
            out.write(reinterpret_cast<const char *>(&p.second), sizeof(p.second));
        }
    }

    void deserialize(std::istream &in)
    {
        in.read(reinterpret_cast<char *>(&numWires), sizeof(numWires));
        in.read(reinterpret_cast<char *>(&numInputs), sizeof(numInputs));
        in.read(reinterpret_cast<char *>(&numNizkInputs), sizeof(numNizkInputs));
        in.read(reinterpret_cast<char *>(&numOutputs), sizeof(numOutputs));
        in.read(reinterpret_cast<char *>(&numVariables), sizeof(numVariables));

        size_t size;

        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        inputWireIds.resize(size);
        in.read(reinterpret_cast<char *>(inputWireIds.data()), size * sizeof(Wire));

        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        outputWireIds.resize(size);
        in.read(reinterpret_cast<char *>(outputWireIds.data()), size * sizeof(Wire));

        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        nizkWireIds.resize(size);
        in.read(reinterpret_cast<char *>(nizkWireIds.data()), size * sizeof(Wire));

        // Deserialize variableMap
        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        variableMap.clear();
        for (size_t i = 0; i < size; i++)
        {
            Wire key;
            unsigned int value;
            in.read(reinterpret_cast<char *>(&key), sizeof(key));
            in.read(reinterpret_cast<char *>(&value), sizeof(value));
            variableMap[key] = value;
        }

        // Deserialize zeropMap
        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        zeropMap.clear();
        for (size_t i = 0; i < size; i++)
        {
            Wire key;
            unsigned int value;
            in.read(reinterpret_cast<char *>(&key), sizeof(key));
            in.read(reinterpret_cast<char *>(&value), sizeof(value));
            zeropMap[key] = value;
        }

        // Deserialize zeropInputWires
        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        zeropInputWires.resize(size);
        for (size_t i = 0; i < size; i++)
        {
            in.read(reinterpret_cast<char *>(&zeropInputWires[i].first), sizeof(Wire));
            in.read(reinterpret_cast<char *>(&zeropInputWires[i].second), sizeof(Wire));
        }
    }

    // Compute the maximum variable index to determine assignment size
    unsigned int getMaxVariableIndex() const
    {
        unsigned int maxIdx = 0;
        for (const auto &kv : variableMap)
        {
            if (kv.second > maxIdx)
                maxIdx = kv.second;
        }
        for (const auto &kv : zeropMap)
        {
            if (kv.second > maxIdx)
                maxIdx = kv.second;
        }
        return maxIdx;
    }
};

class FastWitnessEvaluator
{
public:
    std::vector<FieldT> wireValues;

    // Circuit structure info (loaded from metadata or parsed)
    std::vector<Wire> inputWireIds;
    std::vector<Wire> nizkWireIds;
    std::vector<Wire> outputWireIds;
    unsigned int numInputs = 0;
    unsigned int numNizkInputs = 0;
    unsigned int numOutputs = 0;
    unsigned int numWires = 0;

    FastWitnessEvaluator() {}

    /*
     * Evaluate the circuit: compute all wire values from inputs.
     * This is much faster than CircuitReader because it does NOT
     * build any constraints.
     */
    void evaluate(const char *arithFile, const char *inputFile)
    {
        libff::enter_block("Fast witness evaluation");

        auto start = std::chrono::high_resolution_clock::now();

        // Load input values first
        loadInputs(inputFile);

        // Single pass through .arith - evaluate gates only
        std::ifstream arithfs(arithFile);
        if (!arithfs.good())
        {
            printf("ERROR: Unable to open circuit file: %s\n", arithFile);
            exit(-1);
        }

        std::string line;

        // Pre-allocate reusable buffers (avoid per-line allocation)
        char type[200];
        char inputStr[8192];
        char outputStr[8192];

        // Read header
        std::getline(arithfs, line);
        sscanf(line.c_str(), "total %u", &numWires);
        wireValues.resize(numWires);

        // Field constants (computed once)
        FieldT oneElement = FieldT::one();
        FieldT zeroElement = FieldT::zero();
        FieldT negOneElement = FieldT(-1);

        unsigned int numGateInputs, numGateOutputs;
        Wire wireId;

        // Use larger stream buffer for faster I/O
        char streamBuf[65536];
        arithfs.rdbuf()->pubsetbuf(streamBuf, sizeof(streamBuf));

        while (std::getline(arithfs, line))
        {
            if (line.empty())
                continue;
            if (line[0] == '#')
                continue;

            // Parse input/output/nizk declarations
            if (1 == sscanf(line.c_str(), "input %u", &wireId))
            {
                numInputs++;
                inputWireIds.push_back(wireId);
                continue;
            }
            if (1 == sscanf(line.c_str(), "nizkinput %u", &wireId))
            {
                numNizkInputs++;
                nizkWireIds.push_back(wireId);
                continue;
            }
            if (1 == sscanf(line.c_str(), "output %u", &wireId))
            {
                numOutputs++;
                outputWireIds.push_back(wireId);
                continue;
            }

            // Parse gate operations
            if (5 == sscanf(line.c_str(), "%s in %u <%[^>]> out %u <%[^>]>",
                            type, &numGateInputs, inputStr, &numGateOutputs, outputStr))
            {

                // Parse input wires and get their values
                std::istringstream iss_i(inputStr);
                std::vector<FieldT> inValues;
                inValues.reserve(numGateInputs);
                Wire inWireId;
                while (iss_i >> inWireId)
                {
                    inValues.push_back(wireValues[inWireId]);
                }

                // Parse output wires
                std::istringstream iss_o(outputStr);
                std::vector<Wire> outWires;
                outWires.reserve(numGateOutputs);
                Wire outWireId;
                while (iss_o >> outWireId)
                {
                    outWires.push_back(outWireId);
                }

                // Evaluate based on gate type (fast switch on first char)
                switch (type[0])
                {
                case 'a': // add or assert
                    if (type[1] == 'd')
                    { // add
                        FieldT sum = zeroElement;
                        for (const auto &v : inValues)
                        {
                            sum += v;
                        }
                        wireValues[outWires[0]] = sum;
                    }
                    // assert: no evaluation needed, just constraint
                    break;

                case 'm': // mul
                    wireValues[outWires[0]] = inValues[0] * inValues[1];
                    break;

                case 'x': // xor
                    wireValues[outWires[0]] = (inValues[0] == inValues[1])
                                                  ? zeroElement
                                                  : oneElement;
                    break;

                case 'o': // or
                    wireValues[outWires[0]] = (inValues[0] == zeroElement &&
                                               inValues[1] == zeroElement)
                                                  ? zeroElement
                                                  : oneElement;
                    break;

                case 'z': // zerop (non-zero check)
                    // Output 0: auxiliary (inverse or zero)
                    // Output 1: result (0 if input is zero, 1 otherwise)
                    wireValues[outWires[1]] = (inValues[0] == zeroElement)
                                                  ? zeroElement
                                                  : oneElement;
                    break;

                case 'p': // pack
                {
                    FieldT sum = zeroElement;
                    FieldT two_i = oneElement;
                    for (const auto &v : inValues)
                    {
                        sum += two_i * v;
                        two_i += two_i;
                    }
                    wireValues[outWires[0]] = sum;
                }
                break;

                case 's': // split
                {
                    // Extract bits from input value
                    libff::bigint<FieldT::num_limbs> inBigint = inValues[0].as_bigint();
                    for (size_t i = 0; i < outWires.size(); i++)
                    {
                        wireValues[outWires[i]] = inBigint.test_bit(i) ? oneElement : zeroElement;
                    }
                }
                break;

                case 'c': // const-mul or const-mul-neg
                {
                    FieldT constant;
                    if (strstr(type, "const-mul-neg-"))
                    {
                        char *constStr = type + sizeof("const-mul-neg-") - 1;
                        constant = readFieldElementFromHex(constStr) * negOneElement;
                    }
                    else
                    {
                        char *constStr = type + sizeof("const-mul-") - 1;
                        constant = readFieldElementFromHex(constStr);
                    }
                    wireValues[outWires[0]] = constant * inValues[0];
                }
                break;
                }
            }
        }
        arithfs.close();

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        printf("  Fast evaluation completed in %ld ms\n", duration.count());
        printf("  Wires: %u, Inputs: %u, Outputs: %u, NIZK: %u\n",
               numWires, numInputs, numOutputs, numNizkInputs);

        libff::leave_block("Fast witness evaluation");
    }

    /*
     * Build the variable assignment vector for the prover.
     * Uses the pre-loaded metadata to map wire values to variable indices.
     *
     * @param metadata  Circuit metadata with variable mappings
     * @param fullAssignment  Output vector (will be resized)
     * @param expectedSize  Expected assignment size (from constraint system)
     *                      Pass 0 to auto-detect from metadata
     */
    void buildAssignment(
        const CircuitMetadata &metadata,
        std::vector<FieldT> &fullAssignment,
        size_t expectedSize = 0)
    {
        libff::enter_block("Build variable assignment");

        auto start = std::chrono::high_resolution_clock::now();

        // Determine the correct assignment size
        size_t assignmentSize;
        if (expectedSize > 0)
        {
            // Use the size from constraint system (most reliable)
            assignmentSize = expectedSize;
        }
        else
        {
            // Fall back to computing from metadata
            // The assignment size should be maxVariableIndex + 1
            assignmentSize = metadata.getMaxVariableIndex() + 1;
        }

        // Allocate the full assignment vector
        fullAssignment.clear();
        fullAssignment.resize(assignmentSize, FieldT::zero());

        printf("  Building assignment with %zu variables\n", assignmentSize);
        printf("  variableMap has %zu entries\n", metadata.variableMap.size());
        printf("  zeropMap has %zu entries\n", metadata.zeropMap.size());

        // Map wire values to variable positions
        size_t mappedCount = 0;
        size_t skippedCount = 0;
        for (const auto &kv : metadata.variableMap)
        {
            Wire wireId = kv.first;
            unsigned int varIdx = kv.second;

            if (wireId < wireValues.size() && varIdx < fullAssignment.size())
            {
                fullAssignment[varIdx] = wireValues[wireId];
                mappedCount++;
            }
            else
            {
                skippedCount++;
                if (skippedCount <= 5)
                {
                    printf("  WARNING: Skipping wire %u -> var %u (out of bounds)\n",
                           wireId, varIdx);
                }
            }
        }

        if (skippedCount > 0)
        {
            printf("  WARNING: Skipped %zu out-of-bounds mappings\n", skippedCount);
        }

        // Handle zerop auxiliary variables (need to compute inverse)
        size_t zeropCount = 0;
        for (const auto &zp : metadata.zeropInputWires)
        {
            Wire outputWire = zp.first;
            Wire inputWire = zp.second;

            auto it = metadata.zeropMap.find(outputWire);
            if (it != metadata.zeropMap.end())
            {
                unsigned int auxVarIdx = it->second;

                if (inputWire < wireValues.size() && auxVarIdx < fullAssignment.size())
                {
                    FieldT inputVal = wireValues[inputWire];

                    if (inputVal == FieldT::zero())
                    {
                        fullAssignment[auxVarIdx] = FieldT::zero();
                    }
                    else
                    {
                        fullAssignment[auxVarIdx] = inputVal.inverse();
                    }
                    zeropCount++;
                }
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        printf("  Mapped %zu wire values, %zu zerop auxiliaries\n", mappedCount, zeropCount);
        printf("  Assignment built in %ld ms (%zu variables)\n",
               duration.count(), fullAssignment.size());

        libff::leave_block("Build variable assignment");
    }

private:
    void loadInputs(const char *inputFile)
    {
        std::ifstream inputfs(inputFile);
        if (!inputfs.good())
        {
            printf("ERROR: Unable to open input file: %s\n", inputFile);
            exit(-1);
        }

        std::string line;
        char inputStr[256];

        while (std::getline(inputfs, line))
        {
            if (line.empty())
                continue;

            Wire wireId;
            if (2 == sscanf(line.c_str(), "%u %s", &wireId, inputStr))
            {
                // Ensure wireValues is large enough
                if (wireId >= wireValues.size())
                {
                    wireValues.resize(wireId + 1);
                }
                wireValues[wireId] = readFieldElementFromHex(inputStr);
            }
        }
        inputfs.close();
    }
};

#endif // FAST_WITNESS_EVALUATOR_HPP_