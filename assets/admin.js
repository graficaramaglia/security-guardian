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

	// --- Selezione multipla per la quarantena ---
	function updateCount() {
		var n = $('.sg-pick:checked').length;
		$('#sg-pick-count').text(n);
	}

	$('#sg-select-all, #sg-select-all-2').on('change', function () {
		var checked = this.checked;
		$('.sg-pick').prop('checked', checked);
		$('#sg-select-all, #sg-select-all-2').prop('checked', checked);
		updateCount();
	});

	$(document).on('change', '.sg-pick', function () {
		var total = $('.sg-pick').length;
		var sel = $('.sg-pick:checked').length;
		$('#sg-select-all, #sg-select-all-2').prop('checked', total > 0 && sel === total);
		updateCount();
	});

	$('#sg-bulk-quar').on('click', function () {
		var files = $('.sg-pick:checked').map(function () { return $(this).val(); }).get();
		if (!files.length) {
			alert('Seleziona almeno un file da mettere in quarantena.');
			return;
		}
		if (!confirm('Mettere in quarantena ' + files.length + ' file selezionati? L\'operazione è reversibile dalla pagina Quarantena.')) {
			return;
		}
		var container = $('#sg-bulk-fields').empty();
		files.forEach(function (f) {
			$('<input>', { type: 'hidden', name: 'files[]' }).val(f).appendTo(container);
		});
		$('#sg-bulk-form').trigger('submit');
	});
});
