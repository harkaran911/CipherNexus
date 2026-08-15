/**
 * scene.js — CipherNexus v3 WebGL Background
 * Three.js-powered ambient scene with wireframe polyhedra,
 * 3D particle field, fog, and mouse parallax.
 * Replaces: CSS orbs + 2D canvas particles + grain overlay.
 */

"use strict";

import * as THREE from "../lib/three.module.min.js";

let renderer, scene, camera;
let particles, wireIco, wireOcta, wireRing;
let mouseX = 0,
  mouseY = 0;
let targetCamX = 0,
  targetCamY = 0;
let clock;
let animId = null;
let isVisible = true;

const PARTICLE_COUNT = 250;
const CAM_LERP = 0.03;
const CAM_RANGE = 1.8; // max camera rotation degrees
const PARTICLE_SPREAD = 55;

// ─── Initialize Scene ─────────────────────────────────────────
export function initScene() {
  const canvas = document.getElementById("sceneCanvas");
  if (!canvas) return;

  clock = new THREE.Clock();

  // Renderer
  renderer = new THREE.WebGLRenderer({
    canvas,
    alpha: true,
    antialias: true,
    powerPreference: "low-power",
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setClearColor(0x000000, 0);

  // Scene + Fog
  scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x07070f, 0.022);

  // Camera
  camera = new THREE.PerspectiveCamera(
    55,
    window.innerWidth / window.innerHeight,
    0.1,
    200,
  );
  camera.position.set(0, 0, 30);

  // --- Wireframe polyhedra ---
  const wireMat = new THREE.MeshBasicMaterial({
    color: 0xf5a623,
    wireframe: true,
    transparent: true,
    opacity: 0.045,
  });

  const wireMat2 = new THREE.MeshBasicMaterial({
    color: 0x4ec9e8,
    wireframe: true,
    transparent: true,
    opacity: 0.035,
  });

  const wireMat3 = new THREE.MeshBasicMaterial({
    color: 0xa78bfa,
    wireframe: true,
    transparent: true,
    opacity: 0.03,
  });

  // Icosahedron — large, slow
  const icoGeo = new THREE.IcosahedronGeometry(12, 1);
  wireIco = new THREE.Mesh(icoGeo, wireMat);
  wireIco.position.set(-8, 2, -10);
  scene.add(wireIco);

  // Octahedron — medium, different axis
  const octaGeo = new THREE.OctahedronGeometry(7, 0);
  wireOcta = new THREE.Mesh(octaGeo, wireMat2);
  wireOcta.position.set(10, -4, -15);
  scene.add(wireOcta);

  // Torus ring — subtle accent
  const torusGeo = new THREE.TorusGeometry(9, 0.3, 8, 40);
  wireRing = new THREE.Mesh(torusGeo, wireMat3);
  wireRing.position.set(2, 6, -20);
  wireRing.rotation.x = Math.PI * 0.3;
  scene.add(wireRing);

  // --- 3D Particle Field ---
  const pGeo = new THREE.BufferGeometry();
  const positions = new Float32Array(PARTICLE_COUNT * 3);
  const sizes = new Float32Array(PARTICLE_COUNT);
  const colors = new Float32Array(PARTICLE_COUNT * 3);

  const palette = [
    new THREE.Color(0xf5a623), // amber
    new THREE.Color(0x4ec9e8), // cyan
    new THREE.Color(0xff6b8a), // rose
    new THREE.Color(0xa78bfa), // lilac
    new THREE.Color(0x6ee7b7), // sage
  ];

  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const i3 = i * 3;
    positions[i3] = (Math.random() - 0.5) * PARTICLE_SPREAD;
    positions[i3 + 1] = (Math.random() - 0.5) * PARTICLE_SPREAD;
    positions[i3 + 2] = (Math.random() - 0.5) * PARTICLE_SPREAD - 5;
    sizes[i] = Math.random() * 2.5 + 0.5;

    const c = palette[Math.floor(Math.random() * palette.length)];
    colors[i3] = c.r;
    colors[i3 + 1] = c.g;
    colors[i3 + 2] = c.b;
  }

  pGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  pGeo.setAttribute("size", new THREE.BufferAttribute(sizes, 1));
  pGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));

  const pMat = new THREE.PointsMaterial({
    size: 0.8,
    sizeAttenuation: true,
    transparent: true,
    opacity: 0.25,
    vertexColors: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });

  particles = new THREE.Points(pGeo, pMat);
  scene.add(particles);

  // --- Ambient lights (subtle glow sources) ---
  const ambientLight = new THREE.AmbientLight(0x111122, 0.5);
  scene.add(ambientLight);

  // --- Events ---
  window.addEventListener("resize", onResize, { passive: true });
  document.addEventListener("mousemove", onMouseMove, { passive: true });
  document.addEventListener("visibilitychange", onVisibility);

  // Start render loop
  animate();
}

// ─── Render Loop ──────────────────────────────────────────────
function animate() {
  if (!isVisible) {
    animId = null;
    return;
  }
  animId = requestAnimationFrame(animate);

  const t = clock.getElapsedTime();

  // Polyhedra rotation
  if (wireIco) {
    wireIco.rotation.x = t * 0.06;
    wireIco.rotation.y = t * 0.08;
  }
  if (wireOcta) {
    wireOcta.rotation.x = t * 0.1;
    wireOcta.rotation.z = t * 0.07;
  }
  if (wireRing) {
    wireRing.rotation.y = t * 0.04;
    wireRing.rotation.z = t * 0.03;
  }

  // Particle drift
  if (particles) {
    const pos = particles.geometry.attributes.position.array;
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const i3 = i * 3;
      pos[i3 + 1] += Math.sin(t * 0.3 + i * 0.1) * 0.003; // gentle Y drift
      pos[i3] += Math.cos(t * 0.2 + i * 0.15) * 0.002; // gentle X drift
    }
    particles.geometry.attributes.position.needsUpdate = true;
    particles.rotation.y = t * 0.015;
  }

  // Camera parallax — smooth follow mouse
  targetCamX = mouseX * CAM_RANGE;
  targetCamY = -mouseY * CAM_RANGE;
  camera.rotation.y +=
    (targetCamX * (Math.PI / 180) - camera.rotation.y) * CAM_LERP;
  camera.rotation.x +=
    (targetCamY * (Math.PI / 180) - camera.rotation.x) * CAM_LERP;

  renderer.render(scene, camera);
}

// ─── Tab Switch Transition ────────────────────────────────────
let _transitionActive = false;

export function onTabSwitch(tabId) {
  if (!particles || _transitionActive) return;
  _transitionActive = true;

  // Pulse: briefly scatter particles outward + flash wireframe opacity
  const pos = particles.geometry.attributes.position.array;
  const originalPositions = new Float32Array(pos);

  // Scatter
  for (let i = 0; i < PARTICLE_COUNT; i++) {
    const i3 = i * 3;
    pos[i3] += (Math.random() - 0.5) * 3;
    pos[i3 + 1] += (Math.random() - 0.5) * 3;
    pos[i3 + 2] += (Math.random() - 0.5) * 2;
  }
  particles.geometry.attributes.position.needsUpdate = true;

  // Flash wireframe
  if (wireIco) wireIco.material.opacity = 0.2;
  if (wireOcta) wireOcta.material.opacity = 0.16;

  // Recover over 600ms
  const start = performance.now();
  const duration = 600;

  function recover() {
    const elapsed = performance.now() - start;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3); // easeOutCubic

    for (let i = 0; i < pos.length; i++) {
      pos[i] = pos[i] + (originalPositions[i] - pos[i]) * ease * 0.1;
    }
    particles.geometry.attributes.position.needsUpdate = true;

    if (wireIco) wireIco.material.opacity = 0.2 - (0.2 - 0.08) * ease;
    if (wireOcta) wireOcta.material.opacity = 0.16 - (0.16 - 0.06) * ease;

    if (progress < 1) {
      requestAnimationFrame(recover);
    } else {
      _transitionActive = false;
    }
  }
  requestAnimationFrame(recover);
}

// ─── Event Handlers ───────────────────────────────────────────
function onResize() {
  if (!camera || !renderer) return;
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
}

function onMouseMove(e) {
  // Normalize to -1..1
  mouseX = (e.clientX / window.innerWidth) * 2 - 1;
  mouseY = (e.clientY / window.innerHeight) * 2 - 1;
}

function onVisibility() {
  isVisible = !document.hidden;
  if (isVisible && !animId) animate();
}

// ─── Cleanup ──────────────────────────────────────────────────
export function disposeScene() {
  if (animId) cancelAnimationFrame(animId);
  animId = null;

  window.removeEventListener("resize", onResize);
  document.removeEventListener("mousemove", onMouseMove);
  document.removeEventListener("visibilitychange", onVisibility);

  if (particles) {
    particles.geometry.dispose();
    particles.material.dispose();
  }
  if (wireIco) {
    wireIco.geometry.dispose();
    wireIco.material.dispose();
  }
  if (wireOcta) {
    wireOcta.geometry.dispose();
    wireOcta.material.dispose();
  }
  if (wireRing) {
    wireRing.geometry.dispose();
    wireRing.material.dispose();
  }
  if (renderer) renderer.dispose();
}

// ─── Mission Effects ───────────────────────────────────────────
window.triggerMissionEffect = function(type) {
  if (!particles) return;
  const pMat = particles.material;
  if (type === 'start') {
    if (wireIco) wireIco.material.opacity = 0.01;
    if (wireOcta) wireOcta.material.opacity = 0.01;
  } else if (type === 'success') {
    pMat.color.setHex(0x6ee7b7);
    if (wireIco) {
      wireIco.material.opacity = 0.3;
      wireIco.material.color.setHex(0x6ee7b7);
    }
  } else if (type === 'reset') {
    pMat.color.setHex(0xffffff);
    if (wireIco) {
      wireIco.material.opacity = 0.045;
      wireIco.material.color.setHex(0xf5a623);
    }
    if (wireOcta) wireOcta.material.opacity = 0.035;
  }
};
