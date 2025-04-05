
sources = [
  'libipcon.c',
  'libipcon_priv.c',
  'util.c',
  'libipcon_dbg.c'
]

libipcon = library('ipcon',
  sources: sources,
  install: true,
  dependencies: libnl,
  include_directories: include_directories('../driver'),
  version: '0.0.1',
  soversion: '0'
  )
