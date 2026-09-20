'use strict';
'require view';
'require form';
'require fs';
'require rpc';

/* LuCI 19.07: luci-rpc.getNetworkDevices lists every netdev, wireless ones included
   (network.getDevices() would hide wlan0 and needs many more ACL entries). */
var callNetdevs = rpc.declare({
	object: 'luci-rpc',
	method: 'getNetworkDevices',
	expect: { '': {} }
});

return view.extend({
	load: function () {
		return Promise.all([
			L.resolveDefault(callNetdevs(), {}),
			L.resolveDefault(fs.read('/var/run/nreplatform.status'), '')
		]);
	},

	render: function (data) {
		var names = Object.keys(data[0] || {}).filter(function (n) {
			return n !== 'lo' && !/^ifbnre/.test(n);
		}).sort();
		var status = data[1] || '';
		var m, s, o;

		m = new form.Map('nreplatform', _('NREPlatform LiteV'),
			_('Per-port network emulation: add latency, jitter, packet loss and a maximum speed to an interface. ' +
			  'Direction "to client" is the download of the device behind the port, "from client" its upload.'));

		s = m.section(form.GridSection, 'port', _('Port rules'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = '1';
		o.rmempty = false;
		o.editable = true;

		/* Value + suggestions = drop-down that also accepts typing (e.g. eth0.2) */
		o = s.option(form.Value, 'device', _('Port'));
		o.rmempty = false;
		o.datatype = 'and(maxlength(15),minlength(1))';
		names.forEach(function (n) { o.value(n, n); });

		o = s.option(form.ListValue, 'direction', _('Direction'));
		o.value('egress', _('To client (download)'));
		o.value('ingress', _('From client (upload)'));
		o.value('both', _('Both'));
		o.default = 'both';

		o = s.option(form.Value, 'latency', _('Latency (ms)'));
		o.datatype = 'range(0,60000)';
		o.placeholder = '0';

		o = s.option(form.Value, 'jitter', _('Jitter (ms)'));
		o.datatype = 'range(0,60000)';
		o.placeholder = '0';
		o.modalonly = true;

		o = s.option(form.Value, 'loss', _('Packet loss (%)'));
		o.datatype = 'range(0,100)';
		o.placeholder = '0';

		o = s.option(form.Value, 'rate', _('Max speed (Mbit/s)'));
		o.datatype = 'range(0,100000)';
		o.placeholder = _('0 = unlimited');

		o = s.option(form.Value, 'queue', _('Queue (packets)'));
		o.datatype = 'range(16,10000)';
		o.placeholder = _('auto');
		o.modalonly = true;

		return m.render().then(function (mapEl) {
			return E('div', {}, [
				mapEl,
				E('div', { 'class': 'cbi-section' }, [
					E('h3', {}, _('Live status')),
					E('pre', {}, status || _('nreplatformd is not running.'))
				])
			]);
		});
	}
});
