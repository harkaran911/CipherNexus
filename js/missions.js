/**
 * missions.js — CipherNexus v3 Interactive Missions Engine
 */

window.currentMission = null;
window.missionStep = 0;

const missions = {
  1: {
    title: "The Insider Threat",
    steps: [
      {
        target: ".nav-item[onclick*='steg-pentest']",
        text: "We suspect an employee leaked data inside an image. Let's start by clicking 'Steg Analysis' to use our forensic tools.",
        action: "click",
        setup: () => {}
      },
      {
        target: "#rsFile",
        parentTarget: true, // target the upload-zone parent for spotlight
        text: "RS (Regular-Singular) Analysis detects structural anomalies caused by LSB steganography. Upload any image here to test it.",
        action: "upload",
        setup: () => {
            // switch tab just in case
            const tabBtn = document.querySelector(".nav-item[onclick*='steg-pentest']");
            if (tabBtn && !tabBtn.classList.contains('active')) tabBtn.click();
        }
      },
      {
        target: "#rsOutput",
        text: "Look at the results! When data is hidden, the R+ and R- groups mathematically converge. We have our proof. Let's go extract the data.",
        action: "next",
        setup: () => {
          document.getElementById('aiNextBtn').style.display = 'block';
        }
      },
      {
        target: ".nav-item[onclick*='steg-demo']",
        text: "Click 'Hide & Extract' in the sidebar to switch to the extraction module.",
        action: "click",
        setup: () => {
            document.getElementById('aiNextBtn').style.display = 'none';
        }
      },
      {
        target: "#decodeFile",
        parentTarget: true,
        text: "Drop the same image into the Decode section.",
        action: "upload",
        setup: () => {}
      },
      {
        target: ".btn-rose[onclick='decodeMessage()']",
        text: "Now click 'Extract Hidden Message' to retrieve the stolen flag!",
        action: "click",
        setup: () => {}
      },
      {
        target: null,
        text: "Mission Complete! You successfully used statistical forensics to detect and extract hidden data. The insider has been caught.",
        action: "end",
        setup: () => {
          window.triggerMissionEffect('success');
        }
      }
    ]
  },
  2: {
    title: "ECB is Broken",
    steps: [
      {
        target: ".nav-item[onclick*='aes-lab']",
        text: "AES is powerful, but configuration is everything. Click 'AES Lab' to see why ECB mode is dangerous.",
        action: "click",
        setup: () => {}
      },
      {
        target: "#ecbDemoPlain",
        text: "Scroll down to the 'ECB Pattern Leak Demo'. Type a repetitive phrase here, like 'TOPSECRETTOPSECRET'.",
        action: "input",
        setup: () => {
            const tabBtn = document.querySelector(".nav-item[onclick*='aes-lab']");
            if (tabBtn && !tabBtn.classList.contains('active')) tabBtn.click();
            document.getElementById('ecbDemoPlain').scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      },
      {
        target: "#ecbBlocks",
        text: "Notice the red blocks! ECB encrypts identical plaintext blocks into identical ciphertext blocks. If this were an image, you'd still see the picture!",
        action: "next",
        setup: () => {
            document.getElementById('aiNextBtn').style.display = 'block';
        }
      },
      {
        target: "#cbcBlocks",
        text: "Now look at the green CBC blocks. Because it uses an Initialization Vector (IV) and chaining, the pattern is completely randomized and secure.",
        action: "next",
        setup: () => {}
      },
      {
        target: null,
        text: "Mission Complete! Never use ECB mode for encrypting data. Always use authenticated modes like AES-GCM.",
        action: "end",
        setup: () => {
          document.getElementById('aiNextBtn').style.display = 'none';
          window.triggerMissionEffect('success');
        }
      }
    ]
  },
  3: {
    title: "The Sonic Shadow",
    steps: [
      {
        target: ".nav-item[onclick*='audio-steg']",
        text: "Audio Steganography hides data in sound waves. Let's start by navigating to the Audio Steganography module.",
        action: "click",
        setup: () => {}
      },
      {
        target: "#audioFile",
        parentTarget: true,
        text: "Upload a standard uncompressed .wav file here. This will act as our 'cover' audio.",
        action: "upload",
        setup: () => {
            const tabBtn = document.querySelector(".nav-item[onclick*='audio-steg']");
            if (tabBtn && !tabBtn.classList.contains('active')) tabBtn.click();
        }
      },
      {
        target: "#audioMessageInput",
        text: "Type a secret message into this text area. We will embed this into the Lowest Significant Bits (LSB) of the audio samples.",
        action: "input",
        setup: () => {}
      },
      {
        target: ".btn-cyan[onclick='window.encodeAudioMessage()']",
        text: "Click Encode. The data is now hidden in the audio! But can we detect it visually?",
        action: "click",
        setup: () => {}
      },
      {
        target: ".btn-ghost[onclick='window.playAndVisualize()']",
        text: "Click 'Play & Visualize'. Watch the spectrogram carefully. The bright yellow/cyan noise at the top (high-frequency range) is the acoustic fingerprint of your hidden data!",
        action: "click",
        setup: () => {}
      },
      {
        target: null,
        text: "Mission Complete! You've successfully embedded and visualized audio steganography. Remember, auditory invisibility does not equal forensic invisibility.",
        action: "end",
        setup: () => {
          window.triggerMissionEffect('success');
        }
      }
    ]
  }
};

window.startMission = function(id) {
  if (window.currentMission === id) return;
  window.currentMission = id;
  window.missionStep = 0;
  
  // Close sidebar on mobile
  if (window.innerWidth <= 900) {
      const sidebar = document.getElementById('sidebar');
      const toggle = document.getElementById('sidebarToggle');
      if (sidebar && !sidebar.classList.contains('collapsed')) {
          sidebar.classList.add('collapsed');
          toggle.classList.add('collapsed');
      }
  }

  document.getElementById('missionOverlay').classList.remove('hidden');
  document.getElementById('aiChatBubble').classList.remove('hidden');
  
  window.triggerMissionEffect('start');
  runMissionStep();
};

window.abortMission = function() {
  clearSpotlight();
  document.getElementById('missionOverlay').classList.add('hidden');
  document.getElementById('aiChatBubble').classList.add('hidden');
  document.getElementById('aiNextBtn').style.display = 'none';
  window.currentMission = null;
  window.triggerMissionEffect('reset');
};

window.missionNextStep = function() {
  if (window.currentMission !== null) {
    window.missionStep++;
    runMissionStep();
  }
};

function clearSpotlight() {
  document.querySelectorAll('.spotlight-active').forEach(el => el.classList.remove('spotlight-active'));
}

function runMissionStep() {
  const mission = missions[window.currentMission];
  if (!mission || !mission.steps[window.missionStep]) return;

  const step = mission.steps[window.missionStep];
  clearSpotlight();
  document.getElementById('aiNextBtn').style.display = 'none';

  // Update chat bubble
  const chatText = document.getElementById('aiChatText');
  chatText.replaceChildren();
  const titleEl = document.createElement('strong');
  titleEl.textContent = `[${mission.title}]`;
  chatText.appendChild(titleEl);
  chatText.appendChild(document.createElement('br'));
  chatText.appendChild(document.createTextNode(step.text));

  // Execute setup hook
  if (step.setup) step.setup();

  if (step.action === 'end') {
    document.getElementById('aiNextBtn').style.display = 'block';
    document.getElementById('aiNextBtn').textContent = "Finish";
    document.getElementById('aiNextBtn').onclick = window.abortMission;
    return;
  }

  // Spotlight element
  if (step.target) {
    let el = document.querySelector(step.target);
    if (el) {
      if (step.parentTarget) el = el.parentElement;
      el.classList.add('spotlight-active');
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });

      // Bind action listeners
      if (step.action === 'click') {
        const handler = () => {
          el.removeEventListener('click', handler);
          setTimeout(window.missionNextStep, 300);
        };
        el.addEventListener('click', handler);
      } else if (step.action === 'input') {
        const handler = () => {
          if (el.value.length > 5) {
            el.removeEventListener('input', handler);
            setTimeout(window.missionNextStep, 800);
          }
        };
        el.addEventListener('input', handler);
      } else if (step.action === 'upload') {
        const inputEl = step.parentTarget ? document.querySelector(step.target) : el;
        const handler = () => {
          inputEl.removeEventListener('change', handler);
          // Wait slightly longer for processing
          setTimeout(window.missionNextStep, 1500); 
        };
        inputEl.addEventListener('change', handler);
      }
    }
  }
}

// Intercept specific global functions if needed, but event listeners usually suffice.
