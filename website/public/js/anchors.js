(function () {
  var headings = document.querySelectorAll('.prose h2[id], .prose h3[id]');
  headings.forEach(function (h) {
    var a = document.createElement('a');
    a.className = 'anchor';
    a.href = '#' + h.id;
    a.textContent = '¶';
    a.setAttribute('aria-label', 'Link to ' + h.textContent);
    h.appendChild(a);
  });
})();
