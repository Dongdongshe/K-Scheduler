//===- ExpandTanh.cpp - Code to perform expanding tanh op -----------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements expansion of tanh op.
//
//===----------------------------------------------------------------------===//

#include "PassDetail.h"
#include "mlir/Dialect/StandardOps/IR/Ops.h"
#include "mlir/Dialect/StandardOps/Transforms/Passes.h"
#include "mlir/IR/Builders.h"
#include "mlir/IR/PatternMatch.h"
#include "mlir/IR/TypeUtilities.h"
#include "mlir/Pass/Pass.h"
#include "mlir/Transforms/DialectConversion.h"

using namespace mlir;

namespace {

/// Expands tanh op into
///   1) 1-exp^{-2x} / 1+exp^{-2x}, if x => 0
///   2) exp^{2x}-1 / exp^{2x}+1  , if x < 0
struct TanhOpConverter : public OpRewritePattern<TanhOp> {
public:
  using OpRewritePattern::OpRewritePattern;

  LogicalResult matchAndRewrite(TanhOp op,
                                PatternRewriter &rewriter) const final {
    auto floatType = op.operand().getType();
    Location loc = op.getLoc();
    auto floatOne = rewriter.getFloatAttr(floatType, 1.0);
    auto floatTwo = rewriter.getFloatAttr(floatType, 2.0);
    Value one = rewriter.create<ConstantOp>(loc, floatOne);
    Value two = rewriter.create<ConstantOp>(loc, floatTwo);
    Value doubledX = rewriter.create<MulFOp>(loc, op.operand(), two);

    // Case 1: tanh(x) = 1-exp^{-2x} / 1+exp^{-2x}
    Value negDoubledX = rewriter.create<NegFOp>(loc, doubledX);
    Value exp2x = rewriter.create<ExpOp>(loc, negDoubledX);
    Value dividend = rewriter.create<SubFOp>(loc, one, exp2x);
    Value divisor = rewriter.create<AddFOp>(loc, one, exp2x);
    Value positiveRes = rewriter.create<DivFOp>(loc, dividend, divisor);

    // Case 2: tanh(x) = exp^{2x}-1 / exp^{2x}+1
    exp2x = rewriter.create<ExpOp>(loc, doubledX);
    dividend = rewriter.create<SubFOp>(loc, exp2x, one);
    divisor = rewriter.create<AddFOp>(loc, exp2x, one);
    Value negativeRes = rewriter.create<DivFOp>(loc, dividend, divisor);

    // tanh(x) = x >= 0 ? positiveRes : negativeRes
    auto floatZero = rewriter.getFloatAttr(floatType, 0.0);
    Value zero = rewriter.create<ConstantOp>(loc, floatZero);
    Value cmpRes =
        rewriter.create<CmpFOp>(loc, CmpFPredicate::OGE, op.operand(), zero);
    rewriter.replaceOpWithNewOp<SelectOp>(op, cmpRes, positiveRes, negativeRes);
    return success();
  }
};
} // namespace

void mlir::populateExpandTanhPattern(OwningRewritePatternList &patterns,
                                     MLIRContext *ctx) {
  patterns.insert<TanhOpConverter>(ctx);
}
