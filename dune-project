(lang dune 3.23)

(name if-bridge-filter)

(generate_opam_files true)

(source
 (github username/reponame))

(authors "Author Name <author@example.com>")

(maintainers "Maintainer Name <maintainer@example.com>")

(license LICENSE)

(documentation https://url/to/documentation)

(package
 (name if-bridge-filter)
 (synopsis "A short synopsis")
 (description "A longer description")
 (depends
  ocaml
  libbpf
  ctypes
  ctypes-foreign
  ipaddr)
 (tags
  ("add topics" "to describe" your project)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html
