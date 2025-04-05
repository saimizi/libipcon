include_dir = include_directories([
  '../lib',
  '../driver',
  ])



executable('ipcon_cmd',
  sources: 'ipcon_cmd.c',
  dependencies: libnl,
  include_directories: include_dir,
  link_with: libipcon
  )

executable('ipcon_logger',
  sources: 'ipcon_logger.c',
  dependencies: libnl,
  include_directories: include_dir,
  link_with: libipcon,
  link_args: ['-lm']
  )

executable('ipcon_kevent',
  sources: 'ipcon_kevent.c',
  dependencies: libnl,
  include_directories: include_dir,
  link_with: libipcon
  )
