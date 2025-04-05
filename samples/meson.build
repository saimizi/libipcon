libjslist = library('jslist',
  sources: 'jsutils/jslist/jslist.c',
  )

include_inc = [
  'jsutils/jslist/',
  '../lib',
  '../driver',
  '../logger',
  ]

executable('ipcon_server',
  sources: 'ipcon_server.c',
  include_directories: include_inc,
  dependencies: libnl,
  link_with: [libipcon,libjslist],
  )

executable('ipcon_server_poll',
  sources: 'ipcon_server_poll.c',
  include_directories: include_inc,
  dependencies: libnl,
  link_with: [libipcon,libjslist],
  )

executable('ipcon_sender',
  sources: 'ipcon_sender.c',
  include_directories: include_inc,
  dependencies: libnl,
  link_with: [libipcon,libjslist],
  )

executable('ipcon_user',
  sources: 'ipcon_user.c',
  include_directories: include_inc,
  dependencies: libnl,
  link_with: [libipcon,libjslist],
  )
