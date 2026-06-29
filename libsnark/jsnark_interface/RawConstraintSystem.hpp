/*
 * RawConstraintSystem.hpp
 * 
 * ULTRA-FAST binary serialization for r1cs_constraint_system.
 * 
 * Key optimization: Use reserve() + insert() instead of resize() + memcpy()
 * 
 * Why this might be faster:
 *   - resize(n) = allocate + default-construct n elements + memcpy (overwrites!)
 *   - reserve(n) + insert() = allocate + copy-construct from source (no waste!)
 * 
 * The default construction is WASTED because we immediately overwrite with memcpy.
 * Using insert() constructs directly from the source data.
 */

#ifndef RAW_CONSTRAINT_SYSTEM_HPP
#define RAW_CONSTRAINT_SYSTEM_HPP

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <cstdio>
#include <cstring>
#include <vector>

// ============================================================================
// Raw Constraint System Save Function
// ============================================================================

template<typename FieldT>
bool save_cs_raw(FILE* f, const libsnark::r1cs_constraint_system<FieldT>& cs) {
    using Term = libsnark::linear_term<FieldT>;
    
    size_t num_constraints = cs.num_constraints();
    size_t total_terms = 0;
    for (const auto& constraint : cs.constraints) {
        total_terms += constraint.a.terms.size();
        total_terms += constraint.b.terms.size();
        total_terms += constraint.c.terms.size();
    }
    
    size_t header_size = 3 * sizeof(size_t);
    size_t sizes_size = num_constraints * 3 * sizeof(size_t);
    size_t terms_size = total_terms * sizeof(Term);
    size_t total_size = header_size + sizes_size + terms_size;
    
    std::vector<char> buffer(total_size);
    char* ptr = buffer.data();
    
    size_t primary_size = cs.primary_input_size;
    size_t auxiliary_size = cs.auxiliary_input_size;
    memcpy(ptr, &primary_size, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, &auxiliary_size, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(ptr, &num_constraints, sizeof(size_t)); ptr += sizeof(size_t);
    
    for (const auto& constraint : cs.constraints) {
        size_t a_size = constraint.a.terms.size();
        size_t b_size = constraint.b.terms.size();
        size_t c_size = constraint.c.terms.size();
        memcpy(ptr, &a_size, sizeof(size_t)); ptr += sizeof(size_t);
        memcpy(ptr, &b_size, sizeof(size_t)); ptr += sizeof(size_t);
        memcpy(ptr, &c_size, sizeof(size_t)); ptr += sizeof(size_t);
    }
    
    for (const auto& constraint : cs.constraints) {
        if (!constraint.a.terms.empty()) {
            size_t bytes = constraint.a.terms.size() * sizeof(Term);
            memcpy(ptr, constraint.a.terms.data(), bytes);
            ptr += bytes;
        }
        if (!constraint.b.terms.empty()) {
            size_t bytes = constraint.b.terms.size() * sizeof(Term);
            memcpy(ptr, constraint.b.terms.data(), bytes);
            ptr += bytes;
        }
        if (!constraint.c.terms.empty()) {
            size_t bytes = constraint.c.terms.size() * sizeof(Term);
            memcpy(ptr, constraint.c.terms.data(), bytes);
            ptr += bytes;
        }
    }
    
    if (fwrite(&total_size, sizeof(total_size), 1, f) != 1) return false;
    if (fwrite(buffer.data(), 1, total_size, f) != total_size) return false;
    
    return true;
}

// ============================================================================
// Raw Constraint System Load Function (reserve + insert, no default construction)
// ============================================================================

template<typename FieldT>
bool load_cs_raw(FILE* f, libsnark::r1cs_constraint_system<FieldT>& cs) {
    using Term = libsnark::linear_term<FieldT>;
    
    // Read total size
    size_t total_size;
    if (fread(&total_size, sizeof(total_size), 1, f) != 1) return false;
    
    // Read EVERYTHING in ONE fread
    std::vector<char> buffer(total_size);
    if (fread(buffer.data(), 1, total_size, f) != total_size) return false;
    
    const char* ptr = buffer.data();
    
    // Read header
    size_t primary_size, auxiliary_size, num_constraints;
    memcpy(&primary_size, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(&auxiliary_size, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    memcpy(&num_constraints, ptr, sizeof(size_t)); ptr += sizeof(size_t);
    
    cs.primary_input_size = primary_size;
    cs.auxiliary_input_size = auxiliary_size;
    
    // Read all term counts
    std::vector<size_t> a_sizes(num_constraints);
    std::vector<size_t> b_sizes(num_constraints);
    std::vector<size_t> c_sizes(num_constraints);
    
    for (size_t i = 0; i < num_constraints; ++i) {
        memcpy(&a_sizes[i], ptr, sizeof(size_t)); ptr += sizeof(size_t);
        memcpy(&b_sizes[i], ptr, sizeof(size_t)); ptr += sizeof(size_t);
        memcpy(&c_sizes[i], ptr, sizeof(size_t)); ptr += sizeof(size_t);
    }
    
    // Pointer to term data
    const Term* term_ptr = reinterpret_cast<const Term*>(ptr);
    
    // Build constraints using reserve() + insert() 
    // This avoids default construction - elements are copy-constructed directly from source
    cs.constraints.clear();
    cs.constraints.reserve(num_constraints);
    
    for (size_t i = 0; i < num_constraints; ++i) {
        cs.constraints.emplace_back();  // Add empty constraint
        auto& constraint = cs.constraints.back();
        
        // A terms: reserve space, then insert from source (no default construction!)
        if (a_sizes[i] > 0) {
            constraint.a.terms.reserve(a_sizes[i]);
            constraint.a.terms.insert(constraint.a.terms.end(), term_ptr, term_ptr + a_sizes[i]);
            term_ptr += a_sizes[i];
        }
        
        // B terms
        if (b_sizes[i] > 0) {
            constraint.b.terms.reserve(b_sizes[i]);
            constraint.b.terms.insert(constraint.b.terms.end(), term_ptr, term_ptr + b_sizes[i]);
            term_ptr += b_sizes[i];
        }
        
        // C terms
        if (c_sizes[i] > 0) {
            constraint.c.terms.reserve(c_sizes[i]);
            constraint.c.terms.insert(constraint.c.terms.end(), term_ptr, term_ptr + c_sizes[i]);
            term_ptr += c_sizes[i];
        }
    }
    
    return true;
}

#endif // RAW_CONSTRAINT_SYSTEM_HPP