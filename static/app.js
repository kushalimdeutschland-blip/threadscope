document.addEventListener('DOMContentLoaded', function () {
  var typeInput = document.getElementById('indicator_type');
  var queryInput = document.getElementById('q');

  function activatePanel(panelName) {
    document.querySelectorAll('.main-tab').forEach(function (t) {
      t.classList.toggle('active', t.dataset.panel === panelName);
    });
    document.querySelectorAll('.panel').forEach(function (p) {
      var isActive = p.id === 'panel-' + panelName;
      p.classList.toggle('active', isActive);
      p.hidden = !isActive;
    });
    if (panelName === 'search' && queryInput) {
      queryInput.focus();
    }
  }

  // File | Search tabs
  document.querySelectorAll('.main-tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      activatePanel(tab.dataset.panel);
    });
  });

  var params = new URLSearchParams(window.location.search);
  var initialPanel = params.get('panel');
  if (initialPanel && document.getElementById('panel-' + initialPanel)) {
    activatePanel(initialPanel);
  }

  // Type pills
  document.querySelectorAll('.type-pill').forEach(function (pill) {
    pill.addEventListener('click', function (e) {
      e.preventDefault();
      document.querySelectorAll('.type-pill').forEach(function (p) { p.classList.remove('active'); });
      pill.classList.add('active');
      typeInput.value = pill.dataset.type;
      if (queryInput) {
        queryInput.placeholder = pill.dataset.placeholder || '';
        queryInput.focus();
      }
    });
  });

  // File upload
  var fileInput = document.getElementById('file-input');
  var chooseBtn = document.getElementById('choose-file-btn');
  var dropZone = document.getElementById('drop-zone');
  var fileLabel = document.getElementById('file-label');
  var fileForm = document.getElementById('file-form');

  if (chooseBtn && fileInput) {
    chooseBtn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      fileInput.click();
    });
  }

  if (dropZone && fileInput) {
    dropZone.addEventListener('click', function (e) {
      if (e.target === chooseBtn || chooseBtn.contains(e.target)) return;
      fileInput.click();
    });
  }

  var dynamicCheckbox = document.querySelector('input[name="run_dynamic"]');
  var exeHint = document.getElementById('dynamic-exe-hint');

  function updateDynamicOption() {
    if (!fileInput || !dynamicCheckbox) return;
    var name = (fileInput.files && fileInput.files[0] && fileInput.files[0].name) || '';
    var lower = name.toLowerCase();
    var isApk = lower.endsWith('.apk');
    var isExe = lower.endsWith('.exe');
    if (name && !isApk) {
      dynamicCheckbox.checked = false;
      dynamicCheckbox.disabled = isExe;
    } else {
      dynamicCheckbox.disabled = false;
    }
    if (exeHint) {
      exeHint.hidden = !isExe;
    }
  }

  if (fileInput && fileForm) {
    fileInput.addEventListener('change', function () {
      updateDynamicOption();
      if (fileInput.files && fileInput.files.length) {
        fileLabel.textContent = fileInput.files[0].name;
        if (typeof fileForm.requestSubmit === 'function') {
          fileForm.requestSubmit();
        } else {
          fileForm.submit();
        }
      }
    });
  }

  if (dropZone) {
    dropZone.addEventListener('dragover', function (e) { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', function () { dropZone.classList.remove('dragover'); });
    dropZone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      if (e.dataTransfer.files.length && fileInput) {
        fileInput.files = e.dataTransfer.files;
        fileLabel.textContent = e.dataTransfer.files[0].name;
        if (typeof fileForm.requestSubmit === 'function') {
          fileForm.requestSubmit();
        } else {
          fileForm.submit();
        }
      }
    });
  }

  function copyTextAndFeedback(btn, text) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) return;
    navigator.clipboard.writeText(text).then(function () {
      var label = btn.textContent;
      btn.textContent = 'copied';
      setTimeout(function () { btn.textContent = label; }, 1200);
    });
  }

  document.body.addEventListener('click', function (e) {
    var reportBtn = e.target.closest('.copy-report-btn');
    if (reportBtn && reportBtn.dataset.reportTarget) {
      e.preventDefault();
      var ta = document.getElementById(reportBtn.dataset.reportTarget);
      if (ta && ta.value) {
        copyTextAndFeedback(reportBtn, ta.value);
      }
      return;
    }

    var btn = e.target.closest('.copy-btn');
    if (!btn || !btn.dataset.copy) return;
    e.preventDefault();
    copyTextAndFeedback(btn, btn.dataset.copy);
  });

  document.body.addEventListener('htmx:afterSwap', function (event) {
    if (event.detail.target && event.detail.target.id === 'results') {
      document.body.dispatchEvent(new CustomEvent('historyRefresh'));
    }
  });

  // Allow server HTML error partials (400-level) to display instead of generic failure
  document.body.addEventListener('htmx:beforeSwap', function (event) {
    var status = event.detail.xhr.status;
    if (status >= 400 && status < 500 && event.detail.xhr.responseText) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });

  // HTMX errors → show in results (5xx / network only)
  document.body.addEventListener('htmx:responseError', function (event) {
    var results = document.getElementById('results');
    if (!results) return;
    var status = event.detail && event.detail.xhr ? event.detail.xhr.status : 0;
    if (status >= 400 && status < 500) return;
    var message = 'Request failed. Refresh the page and try again.';
    if (status === 503 || status === 500) {
      message = 'Server error — if feed ingest is running, wait for it to finish and retry.';
    } else if (status === 403) {
      message = 'Session expired. Refresh the page and try again.';
    } else if (status === 429) {
      message = 'Rate limit exceeded. Please wait a moment and try again.';
    }
    results.innerHTML = '<div class="card px-5 py-4 text-center"><p style="color:#f87171">' + message + '</p></div>';
  });
});
