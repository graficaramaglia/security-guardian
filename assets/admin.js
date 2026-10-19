jQuery(function ($) {

	function runScan(btn, statusEl, action, label) {
		btn.prop('disabled', true);
		statusEl.html('<span class="sg-spin dashicons dashicons-update"></span> ' + sgData.scanning);

		$.post(sgData.ajaxurl, { action: action, nonce: sgData.nonce })
			.done(function (res) {
				if (res.success) {
					var n = (typeof res.data.threats !== 'undefined') ? res.data.threats : res.data.findings;
					statusEl.text('Trovati ' + n + ' elementi. Ricarico…');
					setTimeout(function () { location.reload(); }, 900);
				} else {
					statusEl.text('Errore: ' + (res.data || 'sconosciuto'));
					btn.prop('disabled', false);
				}
			})
			.fail(function () {
				statusEl.text('Errore di rete o timeout. Su siti grandi riprova.');
				btn.prop('disabled', false);
			});
	}

	$('#sg-scan-btn').on('click', function () {
		runScan($(this), $('#sg-scan-status'), 'sg_run_scan');
	});

	$('#sg-db-scan-btn').on('click', function () {
		runScan($(this), $('#sg-db-scan-status'), 'sg_run_db_scan');
	});
});
