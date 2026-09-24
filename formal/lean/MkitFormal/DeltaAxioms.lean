import MkitFormal.Delta
-- Axiom audit for the MKIT-25 theorems (run by scripts/difftest-delta.sh, not
-- part of the library): only Lean's standard axioms may appear, never
-- `sorryAx` or `ofReduceBool`.
open MkitFormal.Delta MkitFormal.Delta.Canaries
#print axioms topBit_iff
#print axioms reservedBits_iff
#print axioms readLE_leBytes
#print axioms leBytes_readLE
#print axioms decodeInstrs_encInstrs
#print axioms decode_encode
#print axioms encInstrs_decodeInstrs
#print axioms encode_decode
#print axioms run_ne_oob
#print axioms apply_ne_oob
#print axioms run_sound
#print axioms apply_sound
#print axioms apply_rejects_copy_oob
#print axioms apply_rejects_len_mismatch
#print axioms apply_ok_length
#print axioms run_complete
#print axioms apply_complete
#print axioms encodeFrom_spec
#print axioms encodeWith_wf
#print axioms apply_encodeWith
#print axioms apply_encodeInsertOnly
#print axioms apply_encodeRust
#print axioms noInsertEof_reads_oob
#print axioms apply_sTruncIns
#print axioms noCopyBound_reads_oob
#print axioms apply_sCopyPast
#print axioms sCopyPast_decodes
#print axioms noFinalLen_accepts_short
#print axioms apply_sShort
#print axioms noBaseLen_accepts
#print axioms apply_sWrongBase
#print axioms overrun_kind_only
#print axioms decode_encode_needs_wf
#print axioms decode_encode_needs_wf'
#print axioms decodeLax_not_canonical
#print axioms decodeInstrs_reserved
#print axioms trusting_roundtrip_fails
#print axioms verifying_roundtrip
