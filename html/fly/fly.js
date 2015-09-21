
$(document).ready(function() {
	
    $('h4').wrapInner('<span></span>').append("<a href='#' class='add'>Add Server</a>");

	$('table').each(function() {
		$('tr', this).each(function(i) {
			$(this).prepend('<td>' + (i + 1) + '</td>');
			$(this).append(
				"<td class='last'>" +
					"<a href='#' class='edit'>edit</a>" +
					"<a href='#' class='delete'>delete</a>" +
					"<a href='#' class='save'>save</a>" +
					"<a href='#' class='remove'>confirm</a>" +
				'</td>'
			);
		});
	});

	$('table').prepend(
		'<tr>' +
			"<th width='5%'>#</th>" +
			"<th width='20%'>Server</th>" +
			"<th width='11%'>Backup</th>" +
			"<th width='11%'>Status</th>" +
			"<th width='11%'>Weight</th>" +
			"<th width='11%'>Max fails</th>" +
			"<th width='11%'>Fail timeout</th>" +
			"<th>Operations</th>" +
		'</tr>'
	);

	$(document).on('open', '.add', function() {
		var item = $(this).closest('.item');
		var table = $('table', item);

		var idx = $('tr', table).length;

		$(table).append(
			"<tr class='new'>" +
				"<td>" + idx + "</td>" +
				"<td><input type='text' placeholder='127.0.0.1:8888' class='tw' /></td>" +
				"<td><input type='text' placeholder='no' /></td>" +
				"<td><input type='text' placeholder='normal' /></td>" +
				"<td><input type='text' placeholder='1' /></td>" +
				"<td><input type='text' placeholder='2' /></td>" +
				"<td><input type='text' placeholder='10' /></td>" +
				"<td class='last'>" +
					"<a href='#' class='confirm'>save</a>" +
					"<a href='#' class='cancel'>cancel</a>" +
				"</td>" +
			"</tr>"
		);
	});


	$(document).on('close', '.add', function() {
		var item = $(this).closest('.item');
		var table = $('table', item);

		$('.new', table).fadeOut( function() { $(this).remove(); });
	});


	$(document).on('open', '.edit', function() {
		$(this).addClass('checked');

		var tr = $(this).closest('tr');

		$('td', tr).each(function(i) {
			if (i < 3 || i > 6) {
				return;
			}

			var val = $(this).text();
			$(this).html("<input type='text' value='" + val + "' />");
			$('input', this).attr('old', val);
		});

		$('.save', tr).show();
	});


	$(document).on('close', '.edit', function() {
		$(this).removeClass('checked');

		var tr = $(this).closest('tr');

		$('input[old]', tr).each(function() {
            var td = $(this).closest('td');
            var val = $(this).attr('old');
            td.text(val);
        });

		$('.save', tr).hide();
	});


	$(document).on('open', '.delete', function() {
		$(this).addClass('checked');

		var tr = $(this).closest('tr');
        $('.remove', tr).show();
	});


	$(document).on('close', '.delete', function() {
		$(this).removeClass('checked');

		var tr = $(this).closest('tr');
        $('.remove').hide();
	});


	var lastClick = null;

	$(document).on( "click", ".add, .edit, .delete", function() {

		if (lastClick) {
			if (lastClick == this) {
				var f = 'close';
				$(this).trigger('close');

				lastClick = null;

			} else {
				var f = 'close';
				$(lastClick).trigger('close');
				$(this).trigger('open');

				lastClick = this;
			}

		} else {
			$(this).trigger('open');

			lastClick = this;
		}

		return false;
	});


	$(document).on( "click", ".confirm", function() {
		var tr = $(this).closest('tr');
		var table = tr.closest('tr');
		var item = table.closest('.item');
		var h4 = $('h4', item);

		var ups = $('span', h4).text();

		var ready = $('input:first', tr).val();
		if (!ready) {
			return false;
		}

		var addr = $('input:first', tr).val();
		var backup = $('input:eq(1)', tr).val();
		var status = $('input:eq(2)', tr).val();
		var weight = $('input:eq(3)', tr).val();
		var max_fails = $('input:eq(4)', tr).val();
		var fail_timeout = $('input:eq(5)', tr).val();

		var url = "/fly?ups=" + ups + "&addr=" + addr;

		var params = { 
			act: "add", 
			backup: backup,
			status: status,
			weight: weight,
			max_fails: max_fails,
			fail_timeout: fail_timeout
		};

		$.get(url, params, function(data) {
			$('input', tr).each(function() {
				var td = $(this).closest('td');
				var val = $(this).val();

				if (!val) {
					val = $(this).attr('placeholder');
				}

				td.text(val);
			});

			$('.last', tr).html(
				"<a href='#' class='edit'>edit</a>" +
				"<a href='#' class='delete'>delete</a>" +
				"<a href='#' class='save'>save</a>" +
				"<a href='#' class='remove'>confirm</a>"
			);

			lastClick = null;

		});

		return false;
	});


	$(document).on( "click", ".save", function() {
		var tr = $(this).closest('tr');
		var table = tr.closest('tr');
		var item = table.closest('.item');
		var h4 = $('h4', item);
		var edit = $('.edit', tr);

		var ups = $('span', h4).text();
		var addr = $('td:eq(1)', tr).text();

		var status = $('input:eq(0)', tr).val();
		var weight = $('input:eq(1)', tr).val();
		var max_fails = $('input:eq(2)', tr).val();
		var fail_timeout = $('input:eq(3)', tr).val();

		var url = "/fly?ups=" + ups + "&addr=" + addr;

		var params = { 
			act: "update", 
			status: status,
			weight: weight,
			max_fails: max_fails,
			fail_timeout: fail_timeout
		};

		$.get(url, params, function(data) {

			$('td', tr).each(function(i) {
				if (i < 3 || i > 6) {
					return;
				}

				var val = $('input', this).val();
				$('input', this).attr('old', val);
			});

			edit.trigger('close');
			lastClick = null;

		});

		return false;
	});


	$(document).on( "click", ".remove", function() {
		var tr = $(this).closest('tr');
		var table = tr.closest('tr');
		var item = table.closest('.item');
		var h4 = $('h4', item);

		var ups = $('span', h4).text();
		var addr = $('td:eq(1)', tr).text();

		var url = "/fly?ups=" + ups + "&addr=" + addr;

		var params = { 
			act: "delete"
		};

		$.get(url, params, function(data) {

			$(tr).fadeOut( function() { 
				$(this).remove(); 

				$('tr', table).each(function(i) {
					$('td:first', this).text(i);
				});
			});

			lastClick = null;

		});

		return false;
	});


	$(document).on( "click", ".cancel", function() {
		var item = $(this).closest('.item');

		$('.add', item).trigger('close');
		lastClick = null;

		return false;
	});
});
