; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=thumbv8.1m.main -mattr=+mve.fp -verify-machineinstrs -o - %s | FileCheck %s

define arm_aapcs_vfpcc <8 x half> @test_vdupq_n_f16(float %a.coerce) {
; CHECK-LABEL: test_vdupq_n_f16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmov r0, s0
; CHECK-NEXT:    vdup.16 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = bitcast float %a.coerce to i32
  %tmp.0.extract.trunc = trunc i32 %0 to i16
  %1 = bitcast i16 %tmp.0.extract.trunc to half
  %.splatinsert = insertelement <8 x half> undef, half %1, i32 0
  %.splat = shufflevector <8 x half> %.splatinsert, <8 x half> undef, <8 x i32> zeroinitializer
  ret <8 x half> %.splat
}

define arm_aapcs_vfpcc <4 x float> @test_vdupq_n_f32(float %a) {
; CHECK-LABEL: test_vdupq_n_f32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmov r0, s0
; CHECK-NEXT:    vdup.32 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <4 x float> undef, float %a, i32 0
  %.splat = shufflevector <4 x float> %.splatinsert, <4 x float> undef, <4 x i32> zeroinitializer
  ret <4 x float> %.splat
}

define arm_aapcs_vfpcc <16 x i8> @test_vdupq_n_s8(i8 signext %a) {
; CHECK-LABEL: test_vdupq_n_s8:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vdup.8 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <16 x i8> undef, i8 %a, i32 0
  %.splat = shufflevector <16 x i8> %.splatinsert, <16 x i8> undef, <16 x i32> zeroinitializer
  ret <16 x i8> %.splat
}

define arm_aapcs_vfpcc <8 x i16> @test_vdupq_n_s16(i16 signext %a) {
; CHECK-LABEL: test_vdupq_n_s16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vdup.16 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <8 x i16> undef, i16 %a, i32 0
  %.splat = shufflevector <8 x i16> %.splatinsert, <8 x i16> undef, <8 x i32> zeroinitializer
  ret <8 x i16> %.splat
}

define arm_aapcs_vfpcc <4 x i32> @test_vdupq_n_s32(i32 %a) {
; CHECK-LABEL: test_vdupq_n_s32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vdup.32 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <4 x i32> undef, i32 %a, i32 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> undef, <4 x i32> zeroinitializer
  ret <4 x i32> %.splat
}

define arm_aapcs_vfpcc <16 x i8> @test_vdupq_n_u8(i8 zeroext %a) {
; CHECK-LABEL: test_vdupq_n_u8:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vdup.8 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <16 x i8> undef, i8 %a, i32 0
  %.splat = shufflevector <16 x i8> %.splatinsert, <16 x i8> undef, <16 x i32> zeroinitializer
  ret <16 x i8> %.splat
}

define arm_aapcs_vfpcc <8 x i16> @test_vdupq_n_u16(i16 zeroext %a) {
; CHECK-LABEL: test_vdupq_n_u16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vdup.16 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <8 x i16> undef, i16 %a, i32 0
  %.splat = shufflevector <8 x i16> %.splatinsert, <8 x i16> undef, <8 x i32> zeroinitializer
  ret <8 x i16> %.splat
}

define arm_aapcs_vfpcc <4 x i32> @test_vdupq_n_u32(i32 %a) {
; CHECK-LABEL: test_vdupq_n_u32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vdup.32 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %.splatinsert = insertelement <4 x i32> undef, i32 %a, i32 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> undef, <4 x i32> zeroinitializer
  ret <4 x i32> %.splat
}

define arm_aapcs_vfpcc <8 x half> @test_vdupq_m_n_f16(<8 x half> %inactive, float %a.coerce, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_f16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmov r1, s4
; CHECK-NEXT:    vmsr p0, r0
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.16 q0, r1
; CHECK-NEXT:    bx lr
entry:
  %0 = bitcast float %a.coerce to i32
  %tmp.0.extract.trunc = trunc i32 %0 to i16
  %1 = bitcast i16 %tmp.0.extract.trunc to half
  %2 = zext i16 %p to i32
  %3 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %2)
  %.splatinsert = insertelement <8 x half> undef, half %1, i32 0
  %.splat = shufflevector <8 x half> %.splatinsert, <8 x half> undef, <8 x i32> zeroinitializer
  %4 = select <8 x i1> %3, <8 x half> %.splat, <8 x half> %inactive
  ret <8 x half> %4
}

define arm_aapcs_vfpcc <4 x float> @test_vdupq_m_n_f32(<4 x float> %inactive, float %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_f32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmov r1, s4
; CHECK-NEXT:    vmsr p0, r0
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.32 q0, r1
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %0)
  %.splatinsert = insertelement <4 x float> undef, float %a, i32 0
  %.splat = shufflevector <4 x float> %.splatinsert, <4 x float> undef, <4 x i32> zeroinitializer
  %2 = select <4 x i1> %1, <4 x float> %.splat, <4 x float> %inactive
  ret <4 x float> %2
}

define arm_aapcs_vfpcc <16 x i8> @test_vdupq_m_n_s8(<16 x i8> %inactive, i8 signext %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_s8:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.8 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %0)
  %.splatinsert = insertelement <16 x i8> undef, i8 %a, i32 0
  %.splat = shufflevector <16 x i8> %.splatinsert, <16 x i8> undef, <16 x i32> zeroinitializer
  %2 = select <16 x i1> %1, <16 x i8> %.splat, <16 x i8> %inactive
  ret <16 x i8> %2
}

define arm_aapcs_vfpcc <8 x i16> @test_vdupq_m_n_s16(<8 x i16> %inactive, i16 signext %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_s16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.16 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %0)
  %.splatinsert = insertelement <8 x i16> undef, i16 %a, i32 0
  %.splat = shufflevector <8 x i16> %.splatinsert, <8 x i16> undef, <8 x i32> zeroinitializer
  %2 = select <8 x i1> %1, <8 x i16> %.splat, <8 x i16> %inactive
  ret <8 x i16> %2
}

define arm_aapcs_vfpcc <4 x i32> @test_vdupq_m_n_s32(<4 x i32> %inactive, i32 %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_s32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.32 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %0)
  %.splatinsert = insertelement <4 x i32> undef, i32 %a, i32 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> undef, <4 x i32> zeroinitializer
  %2 = select <4 x i1> %1, <4 x i32> %.splat, <4 x i32> %inactive
  ret <4 x i32> %2
}

define arm_aapcs_vfpcc <16 x i8> @test_vdupq_m_n_u8(<16 x i8> %inactive, i8 zeroext %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_u8:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.8 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %0)
  %.splatinsert = insertelement <16 x i8> undef, i8 %a, i32 0
  %.splat = shufflevector <16 x i8> %.splatinsert, <16 x i8> undef, <16 x i32> zeroinitializer
  %2 = select <16 x i1> %1, <16 x i8> %.splat, <16 x i8> %inactive
  ret <16 x i8> %2
}

define arm_aapcs_vfpcc <8 x i16> @test_vdupq_m_n_u16(<8 x i16> %inactive, i16 zeroext %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_u16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.16 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %0)
  %.splatinsert = insertelement <8 x i16> undef, i16 %a, i32 0
  %.splat = shufflevector <8 x i16> %.splatinsert, <8 x i16> undef, <8 x i32> zeroinitializer
  %2 = select <8 x i1> %1, <8 x i16> %.splat, <8 x i16> %inactive
  ret <8 x i16> %2
}

define arm_aapcs_vfpcc <4 x i32> @test_vdupq_m_n_u32(<4 x i32> %inactive, i32 %a, i16 zeroext %p) {
; CHECK-LABEL: test_vdupq_m_n_u32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vdupt.32 q0, r0
; CHECK-NEXT:    bx lr
entry:
  %0 = zext i16 %p to i32
  %1 = tail call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %0)
  %.splatinsert = insertelement <4 x i32> undef, i32 %a, i32 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> undef, <4 x i32> zeroinitializer
  %2 = select <4 x i1> %1, <4 x i32> %.splat, <4 x i32> %inactive
  ret <4 x i32> %2
}

declare <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32)
declare <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32)
declare <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32)
