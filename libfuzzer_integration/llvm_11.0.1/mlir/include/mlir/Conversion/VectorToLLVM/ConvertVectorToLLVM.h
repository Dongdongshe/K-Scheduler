//===- ConvertVectorToLLVM.h - Utils to convert from the vector dialect ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#ifndef MLIR_CONVERSION_VECTORTOLLVM_CONVERTVECTORTOLLVM_H_
#define MLIR_CONVERSION_VECTORTOLLVM_CONVERTVECTORTOLLVM_H_

#include "mlir/Transforms/DialectConversion.h"

namespace mlir {
class LLVMTypeConverter;
class ModuleOp;
template <typename T>
class OperationPass;

/// Options to control Vector to LLVM lowering.
///
/// This should kept in sync with VectorToLLVM options defined for the
/// ConvertVectorToLLVM pass in include/mlir/Conversion/Passes.td
struct LowerVectorToLLVMOptions {
  bool reassociateFPReductions = false;
  LowerVectorToLLVMOptions &setReassociateFPReductions(bool r) {
    reassociateFPReductions = r;
    return *this;
  }
};

/// Collect a set of patterns to convert from Vector contractions to LLVM Matrix
/// Intrinsics. To lower to assembly, the LLVM flag -lower-matrix-intrinsics
/// will be needed when invoking LLVM.
void populateVectorToLLVMMatrixConversionPatterns(
    LLVMTypeConverter &converter, OwningRewritePatternList &patterns);

/// Collect a set of patterns to convert from the Vector dialect to LLVM.
void populateVectorToLLVMConversionPatterns(
    LLVMTypeConverter &converter, OwningRewritePatternList &patterns,
    bool reassociateFPReductions = false);

/// Create a pass to convert vector operations to the LLVMIR dialect.
std::unique_ptr<OperationPass<ModuleOp>> createConvertVectorToLLVMPass(
    const LowerVectorToLLVMOptions &options = LowerVectorToLLVMOptions());

} // namespace mlir

#endif // MLIR_CONVERSION_VECTORTOLLVM_CONVERTVECTORTOLLVM_H_