// Steps a canvas through the frames `removalStory` (transitions.js) builds,
// with a note panel and Next / Skip-to-result buttons. Shared by build.html
// and index.html so the two pages narrate a collapse the same way.
//
// The panel has two modes: a story (frames, stepping, buttons) and a plain
// note (one line about an insert or update, no buttons). `onIdle` is the
// page's normal redraw, called once a story ends so the real tree is back
// on the canvas.
//
// A frame may carry an `onLeave` callback; it fires once, the first time the
// story moves past that frame (Next or Skip to result). build.html uses it
// to take a row out of the table only after the "about to be removed" step.

import { drawTreeJson } from "./tree-view.js";

export function createStory({ canvas, panel, note, step, nextBtn, finishBtn, onIdle }) {
  let s = null; // { frames, i } while a story is running

  function controls(i) {
    const last = i === s.frames.length - 1;
    note.textContent = s.frames[i].note;
    step.textContent = `step ${i + 1} of ${s.frames.length}`;
    nextBtn.hidden = last;
    finishBtn.hidden = false;
    finishBtn.textContent = last ? "Done" : "Skip to result";
  }

  function show(i) {
    const from = s.frames[s.i];
    const to = s.frames[i];
    if (from.onLeave) {
      const hook = from.onLeave;
      from.onLeave = undefined;
      hook();
    }
    s.i = i;
    controls(i);
    drawTreeJson(canvas, JSON.stringify(to.view), rerender, {
      from: JSON.stringify(from.view),
      focus: to.focus,
      marks: to.marks,
      fromMarks: from.marks,
    });
  }

  // A click on the strip mid-story redraws the CURRENT frame with the new
  // selection, rather than jumping to the real tree.
  function rerender() {
    if (!s) {
      onIdle();
      return;
    }
    const f = s.frames[s.i];
    drawTreeJson(canvas, JSON.stringify(f.view), rerender, { marks: f.marks });
  }

  const api = {
    active: () => s !== null,

    // Frame 0 is shown as it is -- the tree before the change, with the
    // node about to go marked -- and nothing moves until Next.
    start(frames) {
      s = { frames, i: 0 };
      panel.hidden = false;
      controls(0);
      const f = frames[0];
      drawTreeJson(canvas, JSON.stringify(f.view), rerender, { focus: f.focus, marks: f.marks });
    },

    // One-line panel without steps.
    note(text) {
      s = null;
      panel.hidden = false;
      note.textContent = text;
      step.textContent = "";
      nextBtn.hidden = true;
      finishBtn.hidden = true;
    },

    // Hide the panel and drop any story. `redraw` puts the real tree back.
    end(redraw = true) {
      const showing = s !== null || !panel.hidden;
      s = null;
      panel.hidden = true;
      if (redraw && showing) onIdle();
    },

    rerender,
  };

  nextBtn.addEventListener("click", () => {
    if (s && s.i < s.frames.length - 1) show(s.i + 1);
  });
  finishBtn.addEventListener("click", () => {
    if (!s) return;
    if (s.i < s.frames.length - 1) show(s.frames.length - 1);
    else api.end(true);
  });

  return api;
}
