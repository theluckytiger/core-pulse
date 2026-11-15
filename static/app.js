// Draws a chart for every <script class="chart-data"> block, using uPlot
// when it is loaded. Charts are redrawn after htmx swaps in fresh data.
(function () {
  "use strict";

  function color(index) {
    var value = getComputedStyle(document.documentElement).getPropertyValue("--series-" + (index + 1));
    return value.trim() || "#888";
  }

  function draw(root) {
    if (!window.uPlot) return;
    root.querySelectorAll("script.chart-data").forEach(function (node) {
      var target = document.getElementById(node.dataset.target);
      if (!target) return;
      var data = JSON.parse(node.textContent);
      if (!data.times || data.times.length === 0) return;

      var series = [{}].concat(data.series.map(function (s, i) {
        return { label: s.name, stroke: color(i), width: 1.5, points: { show: false } };
      }));
      var values = [data.times].concat(data.series.map(function (s) { return s.values; }));
      var axis = { stroke: getComputedStyle(document.body).color, grid: { stroke: "rgba(128,128,128,0.15)" } };

      target.textContent = "";
      new uPlot({
        width: target.clientWidth,
        height: 220,
        series: series,
        axes: [axis, axis],
        cursor: { drag: { x: false, y: false } }
      }, values, target);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    draw(document);
    document.body.addEventListener("htmx:afterSwap", function (event) { draw(event.target); });
  });

  var resizing;
  window.addEventListener("resize", function () {
    clearTimeout(resizing);
    resizing = setTimeout(function () { draw(document); }, 200);
  });
})();
