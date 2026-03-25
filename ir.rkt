#lang racket/base

;; ============================================================
;; wirey Intermediate Representation
;;
;; The single source of truth for a wire structure's layout.
;; The macro parses syntax into this IR.
;; The codec encodes/decodes from this IR.
;; Accessors, match expanders, and encode formals derive from this IR.
;; ============================================================

(provide
 ;; Protocol elements (the tree nodes)
 wire-field wire-field?
 wire-field-name wire-field-type wire-field-width wire-field-byte-order
 wire-field-options

 wire-case wire-case?
 wire-case-discriminator wire-case-branches

 wire-case-branch wire-case-branch?
 wire-case-branch-predicate wire-case-branch-elements

 wire-bitfield-group wire-bitfield-group?
 wire-bitfield-group-fields wire-bitfield-group-bit-order wire-bitfield-group-total-bits

 wire-bit-field wire-bit-field?
 wire-bit-field-name wire-bit-field-type wire-bit-field-width wire-bit-field-options

 wire-padding wire-padding?
 wire-padding-width

 ;; Protocol descriptor
 wire-protocol wire-protocol?
 wire-protocol-name wire-protocol-elements wire-protocol-options

 ;; Field width types
 width-fixed width-fixed? width-fixed-value
 width-field-ref width-field-ref? width-field-ref-name
 width-compute width-compute? width-compute-fn

 ;; Option accessors (hash-based, extensible)
 wire-option)

;; ============================================================
;; Field width: how wide is this field?
;; ============================================================

(struct width-fixed (value) #:transparent)        ;; exact positive integer
(struct width-field-ref (name) #:transparent)      ;; value of another field
(struct width-compute (fn) #:transparent)           ;; (lookup-fn → integer)

;; ============================================================
;; Protocol elements: the nodes of the element tree
;; ============================================================

;; A byte-aligned field.
;; Options is an immutable hash with any of:
;;   'compute    — (bytes → value) for auto-computed fields
;;   'contract   — (value → boolean) for validation
;;   'present-when — (lookup → boolean) for conditional presence
;;   'default    — default value for encode
;;   'terminator — byte value for null-terminated strings
;;   'repeat     — width-fixed | width-field-ref | width-compute
;;   'repeat-until — (value → boolean) for sentinel-terminated arrays
;;   'enum       — wire-enum for symbol ↔ integer mapping
;;   'struct-ref — symbol (name of embedded wire struct)
;;   'encode-transform — (racket-value → wire-value)
;;   'decode-transform — (wire-value → racket-value)
(struct wire-field (name type width byte-order options) #:transparent)

;; A sub-byte (bit-level) field within a bitfield group.
(struct wire-bit-field (name type width options) #:transparent)

;; A group of contiguous bit-level fields packed into bytes.
;; total-bits must be a multiple of 8.
(struct wire-bitfield-group (fields bit-order total-bits) #:transparent)

;; N-way case dispatch: decode/encode a different set of elements
;; depending on a previously decoded field's value.
(struct wire-case (discriminator branches) #:transparent)

;; A single branch of a case dispatch.
;; predicate: exact value (integer, string) or (value → boolean).
;; elements: list of protocol elements (recursive).
(struct wire-case-branch (predicate elements) #:transparent)

;; Explicit padding (zero bytes, skipped on decode).
(struct wire-padding (width) #:transparent)

;; ============================================================
;; Protocol descriptor: the top-level IR
;; ============================================================

;; A wire protocol is a name + a list of elements + options.
;; Options is an immutable hash with any of:
;;   'byte-order — default byte order for fields
;;   'bit-order  — default bit order for bitfield groups
;;   'alignment  — default alignment for fields
;;   'encode     — (racket-value → field-hash) for value-level encode
;;   'decode     — (field-hash → racket-value) for value-level decode
(struct wire-protocol (name elements options) #:transparent)

;; ============================================================
;; Helpers
;; ============================================================

;; Get an option from an options hash, or #f.
(define (wire-option opts key)
  (hash-ref opts key #f))
