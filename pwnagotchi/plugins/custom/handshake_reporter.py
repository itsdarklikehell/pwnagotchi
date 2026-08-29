import logging
import os

import pwnagotchi.plugins as plugins


class HandshakeReporter(plugins.Plugin):
    """
    Reports captured WPA handshakes to the pwnagotchi web UI.

    Whenever a new handshake is captured (on_handshake), the plugin counts the
    total number of .pcap files in the handshake directory and shows it as a UI
    badge. It can optionally append a one-line CSV log of each capture so you can
    track what was cracked later. Useful for a wall-mounted unit where you just
    want a live "X handshakes" counter instead of SSH-ing in.

    Options:
        path:     directory that holds captured handshakes (default: /root/handshakes)
        log_file: if set, append "bssid,station,file,epoch" lines here
        badge:    UI label for the counter (default: HS)
    """

    __author__ = 'corneel'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Counts captured handshakes and shows a live badge on the UI.'

    def __init__(self):
        self._count = 0
        self._path = '/root/handshakes'
        self._log_file = None
        self._badge = 'HS'

    # called when the plugin is loaded; read options and prime the counter
    def on_loaded(self):
        opts = getattr(self, 'options', None) or {}
        self._path = opts.get('path', '/root/handshakes')
        self._log_file = opts.get('log_file')
        self._badge = opts.get('badge', 'HS')
        self._count = self._count_pcaps()
        logging.info('[handshake_reporter] watching %s (%d pcaps so far)', self._path, self._count)

    def _count_pcaps(self):
        try:
            return len([f for f in os.listdir(self._path) if f.endswith('.pcap')])
        except OSError:
            return 0

    # called when the UI elements are set up
    def on_ui_setup(self, ui):
        from pwnagotchi.ui.components import LabeledValue
        from pwnagotchi.ui.view import BLACK
        import pwnagotchi.ui.fonts as fonts

        ui.add_element(
            'handshake_count',
            LabeledValue(
                color=BLACK,
                label=self._badge,
                value='%d' % self._count,
                position=(ui.width() - 28, 0),
                label_font=fonts.Bold,
                text_font=fonts.Medium,
            ),
        )

    # called when the UI is refreshed
    def on_ui_update(self, ui):
        ui.set('handshake_count', '%d' % self._count)

    # called when a new handshake is captured
    def on_handshake(self, agent, filename, access_point, client_station):
        self._count += 1
        logging.info('[handshake_reporter] handshake #%d captured: %s', self._count, filename)
        if self._log_file:
            try:
                with open(self._log_file, 'a', encoding='utf-8') as fh:
                    fh.write('%s,%s,%s,%d\n' % (
                        access_point if isinstance(access_point, str) else access_point.get('mac', ''),
                        client_station if isinstance(client_station, str) else client_station.get('mac', ''),
                        filename,
                        int(os.path.getmtime(filename)) if filename and os.path.exists(filename) else 0,
                    ))
            except OSError as exc:
                logging.warning('[handshake_reporter] could not write log: %s', exc)
