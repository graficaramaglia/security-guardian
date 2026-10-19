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

	// --- Selezione multipla e azione in blocco (riutilizzabile) ---
	// opts: pick (classe checkbox), all (selettore "seleziona tutti"),
	//       count, button, form, fields (contenitore), field (name[]),
	//       confirm (messaggio), empty (messaggio se nulla selezionato).
	function setupBulk(opts) {
		function update() {
			var total = $(opts.pick).length;
			var sel = $(opts.pick + ':checked').length;
			$(opts.count).text(sel);
			$(opts.all).prop('checked', total > 0 && sel === total);
		}

		$(opts.all).on('change', function () {
			$(opts.pick).prop('checked', this.checked);
			update();
		});
		$(document).on('change', opts.pick, update);

		$(opts.button).on('click', function () {
			var vals = $(opts.pick + ':checked').map(function () { return $(this).val(); }).get();
			if (!vals.length) {
				alert(opts.empty);
				return;
			}
			if (!confirm(opts.confirm.replace('%d', vals.length))) {
				return;
			}
			var container = $(opts.fields).empty();
			vals.forEach(function (v) {
				$('<input>', { type: 'hidden', name: opts.field }).val(v).appendTo(container);
			});
			$(opts.form).trigger('submit');
		});

		update();
	}

	// Quarantena file (pagina Scansione)
	setupBulk({
		pick: '.sg-pick',
		all: '#sg-select-all, #sg-select-all-2',
		count: '#sg-pick-count',
		button: '#sg-bulk-quar',
		form: '#sg-bulk-form',
		fields: '#sg-bulk-fields',
		field: 'files[]',
		confirm: 'Mettere in quarantena %d file selezionati? L\'operazione è reversibile dalla pagina Quarantena.',
		empty: 'Seleziona almeno un file da mettere in quarantena.'
	});

	// Pulizia database (pagina Database)
	setupBulk({
		pick: '.sg-pick-db',
		all: '#sg-select-all-db, #sg-select-all-db-2',
		count: '#sg-pick-count-db',
		button: '#sg-bulk-clean',
		form: '#sg-bulk-form-db',
		fields: '#sg-bulk-fields-db',
		field: 'items[]',
		confirm: 'Pulire %d elementi selezionati? Gli originali vengono salvati nella quarantena del database e sono ripristinabili.',
		empty: 'Seleziona almeno un elemento da pulire.'
	});
});
