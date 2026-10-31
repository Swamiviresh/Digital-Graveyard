import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.180.0/build/three.module.js';

const mount = document.getElementById('threejs-container-ANIMATION_17');
if (!mount) throw new Error('Digital Graveyard 3D mount was not found.');

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(36, 1, 0.1, 100);
camera.position.set(0, 0, 10.5);

const renderer = new THREE.WebGLRenderer({
  alpha: true,
  antialias: true,
  powerPreference: 'high-performance',
});
renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.6));
renderer.setSize(mount.clientWidth || 560, mount.clientHeight || 540);
renderer.outputColorSpace = THREE.SRGBColorSpace;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.15;
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
renderer.domElement.setAttribute('aria-label', 'Interactive three-dimensional Halloween scene with a ghost, pumpkins and a vampire');
renderer.domElement.setAttribute('role', 'img');
mount.appendChild(renderer.domElement);

scene.add(new THREE.AmbientLight(0x9a75c8, 1.35));
const keyLight = new THREE.DirectionalLight(0xf5eaff, 2.4);
keyLight.position.set(-3.5, 5, 7);
keyLight.castShadow = true;
scene.add(keyLight);
const purpleRim = new THREE.PointLight(0x9b4dff, 28, 14);
purpleRim.position.set(-3.6, 2.8, 2.5);
scene.add(purpleRim);
const warmRim = new THREE.PointLight(0xff7a21, 16, 12);
warmRim.position.set(3.2, -2, 2.2);
scene.add(warmRim);

const modelRoot = new THREE.Group();
scene.add(modelRoot);

function makeGhost() {
  const group = new THREE.Group();
  const bodyGeometry = new THREE.SphereGeometry(0.96, 48, 36);
  const position = bodyGeometry.attributes.position;
  for (let i = 0; i < position.count; i += 1) {
    const x = position.getX(i);
    const y = position.getY(i);
    const z = position.getZ(i);
    if (y < -0.05) {
      const angle = Math.atan2(z, x);
      const ripple = Math.sin(angle * 7) * 0.10 + Math.sin(angle * 4 + 0.5) * 0.055;
      position.setY(i, y * 1.65 + ripple);
      const widen = 1 + Math.abs(y) * 0.18 + ripple * 0.12;
      position.setX(i, x * widen);
      position.setZ(i, z * widen);
    }
  }
  bodyGeometry.computeVertexNormals();
  const bodyMaterial = new THREE.MeshPhysicalMaterial({
    color: 0xf1edff,
    roughness: 0.16,
    metalness: 0.02,
    transmission: 0.38,
    thickness: 0.8,
    transparent: true,
    opacity: 0.88,
    emissive: 0x6f35a8,
    emissiveIntensity: 0.24,
    clearcoat: 0.85,
  });
  const body = new THREE.Mesh(bodyGeometry, bodyMaterial);
  body.castShadow = true;
  group.add(body);

  const eyeMaterial = new THREE.MeshStandardMaterial({
    color: 0x171022,
    emissive: 0x6b21a8,
    emissiveIntensity: 0.65,
    roughness: 0.25,
  });
  const eyeGeometry = new THREE.SphereGeometry(0.095, 20, 16);
  [-1, 1].forEach((side) => {
    const eye = new THREE.Mesh(eyeGeometry, eyeMaterial);
    eye.position.set(side * 0.27, 0.15, 0.79);
    eye.scale.set(0.8, 1.25, 0.55);
    group.add(eye);
    const glint = new THREE.Mesh(
      new THREE.SphereGeometry(0.025, 10, 8),
      new THREE.MeshBasicMaterial({ color: 0xffffff }),
    );
    glint.position.set(side * 0.27 + 0.025, 0.18, 0.835);
    group.add(glint);
  });

  const mouth = new THREE.Mesh(
    new THREE.TorusGeometry(0.105, 0.018, 10, 24, Math.PI),
    new THREE.MeshBasicMaterial({ color: 0x37204d }),
  );
  mouth.position.set(0, -0.11, 0.83);
  mouth.rotation.z = Math.PI;
  group.add(mouth);

  const handGeometry = new THREE.SphereGeometry(0.22, 20, 14);
  const leftHand = new THREE.Mesh(handGeometry, bodyMaterial);
  const rightHand = new THREE.Mesh(handGeometry, bodyMaterial);
  leftHand.position.set(-0.88, -0.05, 0.15);
  rightHand.position.set(0.88, -0.05, 0.15);
  leftHand.scale.set(0.75, 0.85, 0.8);
  rightHand.scale.copy(leftHand.scale);
  group.add(leftHand, rightHand);
  group.userData.leftHand = leftHand;
  group.userData.rightHand = rightHand;
  group.position.set(-0.12, 0.5, 0.45);
  group.scale.setScalar(1.18);
  return group;
}

function makePumpkin(scale, x, y, z, rotation = 0) {
  const group = new THREE.Group();
  const geometry = new THREE.SphereGeometry(0.72, 48, 36);
  const position = geometry.attributes.position;
  for (let i = 0; i < position.count; i += 1) {
    const px = position.getX(i);
    const py = position.getY(i);
    const pz = position.getZ(i);
    const angle = Math.atan2(pz, px);
    const ridge = 1 + 0.075 * Math.cos(angle * 9);
    position.setX(i, px * ridge);
    position.setZ(i, pz * ridge);
    position.setY(i, py * 0.82);
  }
  geometry.computeVertexNormals();
  const skin = new THREE.MeshStandardMaterial({
    color: 0xef781d,
    roughness: 0.62,
    metalness: 0.02,
  });
  const body = new THREE.Mesh(geometry, skin);
  body.castShadow = true;
  body.receiveShadow = true;
  group.add(body);

  const stem = new THREE.Mesh(
    new THREE.CylinderGeometry(0.075, 0.12, 0.34, 12),
    new THREE.MeshStandardMaterial({ color: 0x47552b, roughness: 0.82 }),
  );
  stem.position.y = 0.68;
  stem.rotation.z = -0.18;
  group.add(stem);

  // Glowing face pieces sit on the curved surface of the pumpkin's real 3D mesh.
  const glow = new THREE.MeshBasicMaterial({ color: 0xffd36a });
  const darkCut = new THREE.MeshBasicMaterial({ color: 0x3b1609 });
  const eyeGeometry = new THREE.ConeGeometry(0.14, 0.24, 3);
  eyeGeometry.rotateX(Math.PI / 2);
  [-1, 1].forEach((side) => {
    const eye = new THREE.Mesh(eyeGeometry, glow);
    eye.position.set(side * 0.23, 0.12, 0.585);
    eye.rotation.z = side * -0.10;
    group.add(eye);
  });
  const mouthShape = new THREE.Shape();
  mouthShape.moveTo(-0.30, -0.13);
  mouthShape.lineTo(-0.20, -0.28);
  mouthShape.lineTo(-0.10, -0.17);
  mouthShape.lineTo(0, -0.30);
  mouthShape.lineTo(0.11, -0.17);
  mouthShape.lineTo(0.22, -0.27);
  mouthShape.lineTo(0.30, -0.13);
  mouthShape.lineTo(0.24, -0.02);
  mouthShape.lineTo(-0.23, -0.02);
  mouthShape.closePath();
  const mouth = new THREE.Mesh(new THREE.ShapeGeometry(mouthShape), darkCut);
  mouth.position.set(0, 0, 0.62);
  group.add(mouth);
  const inner = new THREE.PointLight(0xff8b24, 1.8, 3.2);
  inner.position.set(0, 0.05, 0.38);
  group.add(inner);

  group.scale.setScalar(scale);
  group.position.set(x, y, z);
  group.rotation.y = rotation;
  group.userData.glow = inner;
  return group;
}

function makeVampire() {
  const group = new THREE.Group();
  const skin = new THREE.MeshStandardMaterial({ color: 0xe6dce8, roughness: 0.42 });
  const suit = new THREE.MeshStandardMaterial({ color: 0x15121e, roughness: 0.48 });
  const cape = new THREE.MeshStandardMaterial({ color: 0x090811, roughness: 0.52, side: THREE.DoubleSide });
  const crimson = new THREE.MeshStandardMaterial({ color: 0x781f35, roughness: 0.6, side: THREE.DoubleSide });

  const head = new THREE.Mesh(new THREE.SphereGeometry(0.34, 28, 22), skin);
  head.position.y = 0.66;
  head.castShadow = true;
  group.add(head);

  const hair = new THREE.Mesh(
    new THREE.SphereGeometry(0.355, 28, 16, 0, Math.PI * 2, 0, Math.PI * 0.53),
    new THREE.MeshStandardMaterial({ color: 0x101018, roughness: 0.26 }),
  );
  hair.position.set(0, 0.78, -0.025);
  group.add(hair);

  const torso = new THREE.Mesh(new THREE.CylinderGeometry(0.25, 0.34, 0.78, 24), suit);
  torso.position.y = 0.06;
  torso.castShadow = true;
  group.add(torso);

  const neck = new THREE.Mesh(new THREE.CylinderGeometry(0.105, 0.12, 0.2, 16), skin);
  neck.position.y = 0.43;
  group.add(neck);

  // Two layered extruded cape panels make the vampire a real multi-part 3D character.
  const capeShape = new THREE.Shape();
  capeShape.moveTo(-0.24, 0.42);
  capeShape.lineTo(0.24, 0.42);
  capeShape.lineTo(0.75, -0.52);
  capeShape.quadraticCurveTo(0, -0.25, -0.75, -0.52);
  capeShape.closePath();
  const capeGeometry = new THREE.ExtrudeGeometry(capeShape, { depth: 0.055, bevelEnabled: true, bevelSegments: 2, steps: 1, bevelSize: 0.025, bevelThickness: 0.025 });
  const capeOuter = new THREE.Mesh(capeGeometry, cape);
  capeOuter.position.set(0, 0.28, -0.22);
  capeOuter.castShadow = true;
  group.add(capeOuter);
  const capeInner = new THREE.Mesh(capeGeometry, crimson);
  capeInner.position.set(0, 0.28, -0.29);
  capeInner.scale.set(0.92, 0.95, 0.72);
  group.add(capeInner);

  const collarShape = new THREE.Shape();
  collarShape.moveTo(-0.26, 0);
  collarShape.lineTo(-0.48, 0.42);
  collarShape.lineTo(-0.11, 0.31);
  collarShape.lineTo(0, 0.04);
  collarShape.lineTo(0.11, 0.31);
  collarShape.lineTo(0.48, 0.42);
  collarShape.lineTo(0.26, 0);
  collarShape.closePath();
  const collar = new THREE.Mesh(new THREE.ShapeGeometry(collarShape), crimson);
  collar.position.set(0, 0.22, 0.05);
  group.add(collar);

  const eyeMaterial = new THREE.MeshBasicMaterial({ color: 0xd5264f });
  [-1, 1].forEach((side) => {
    const eye = new THREE.Mesh(new THREE.SphereGeometry(0.045, 12, 10), eyeMaterial);
    eye.position.set(side * 0.12, 0.68, 0.30);
    group.add(eye);
  });
  const fangMaterial = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.3 });
  [-1, 1].forEach((side) => {
    const fang = new THREE.Mesh(new THREE.ConeGeometry(0.035, 0.10, 8), fangMaterial);
    fang.position.set(side * 0.095, 0.49, 0.29);
    fang.rotation.x = Math.PI;
    group.add(fang);
  });

  const armGeometry = new THREE.CapsuleGeometry(0.07, 0.34, 4, 10);
  [-1, 1].forEach((side) => {
    const arm = new THREE.Mesh(armGeometry, suit);
    arm.position.set(side * 0.34, 0.05, 0.02);
    arm.rotation.z = side * -0.48;
    group.add(arm);
  });

  group.scale.setScalar(0.93);
  group.position.set(1.52, -0.04, 0.25);
  return group;
}

const ghost = makeGhost();
const pumpkinLeft = makePumpkin(0.82, -1.72, -1.55, 0.85, -0.22);
const pumpkinRight = makePumpkin(0.62, 1.58, -1.65, 0.55, 0.22);
const vampire = makeVampire();
modelRoot.add(ghost, pumpkinLeft, pumpkinRight, vampire);

// A subtle arc behind the characters adds depth without becoming another UI card.
const halo = new THREE.Mesh(
  new THREE.TorusGeometry(1.88, 0.012, 8, 120, Math.PI * 1.72),
  new THREE.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.36 }),
);
halo.rotation.z = -0.32;
halo.position.set(-0.08, 0.18, -1.25);
modelRoot.add(halo);

const particleCount = 90;
const particlePositions = new Float32Array(particleCount * 3);
for (let i = 0; i < particleCount; i += 1) {
  particlePositions[i * 3] = (Math.random() - 0.5) * 6.4;
  particlePositions[i * 3 + 1] = (Math.random() - 0.5) * 5.5;
  particlePositions[i * 3 + 2] = -1.9 + Math.random() * 2.2;
}
const particleGeometry = new THREE.BufferGeometry();
particleGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
const particleMaterial = new THREE.PointsMaterial({ color: 0xc084fc, size: 0.026, transparent: true, opacity: 0.68, sizeAttenuation: true });
const particles = new THREE.Points(particleGeometry, particleMaterial);
scene.add(particles);

const pointer = new THREE.Vector2(0, 0);
const pointerTarget = new THREE.Vector2(0, 0);
const onPointerMove = (event) => {
  const rect = mount.getBoundingClientRect();
  pointerTarget.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  pointerTarget.y = -(((event.clientY - rect.top) / rect.height) * 2 - 1);
};
mount.addEventListener('pointermove', onPointerMove, { passive: true });
mount.addEventListener('pointerleave', () => pointerTarget.set(0, 0), { passive: true });

const clock = new THREE.Clock();
let isVisible = true;
const observer = new IntersectionObserver(([entry]) => { isVisible = entry.isIntersecting; });
observer.observe(mount);

function resize() {
  const width = Math.max(1, mount.clientWidth);
  const height = Math.max(1, mount.clientHeight);
  camera.aspect = width / height;
  camera.updateProjectionMatrix();
  renderer.setSize(width, height, false);
}
const resizeObserver = new ResizeObserver(resize);
resizeObserver.observe(mount);
resize();

renderer.setAnimationLoop(() => {
  if (!isVisible) return;
  const time = clock.getElapsedTime();
  const motion = reducedMotion ? 0.15 : 1;
  pointer.lerp(pointerTarget, 0.035);

  ghost.position.y = 0.5 + Math.sin(time * 1.15) * 0.16 * motion + pointer.y * 0.08;
  ghost.position.x = -0.12 + Math.sin(time * 0.62) * 0.08 * motion + pointer.x * 0.12;
  ghost.rotation.y = Math.sin(time * 0.58) * 0.15 * motion + pointer.x * 0.12;
  ghost.rotation.z = Math.sin(time * 0.85) * 0.035 * motion;
  ghost.userData.leftHand.position.y = -0.05 + Math.sin(time * 1.7) * 0.055 * motion;
  ghost.userData.rightHand.position.y = -0.05 + Math.cos(time * 1.5) * 0.055 * motion;

  pumpkinLeft.rotation.y = -0.22 + Math.sin(time * 0.42) * 0.12 * motion + pointer.x * 0.07;
  pumpkinLeft.position.y = -1.55 + Math.sin(time * 0.9) * 0.055 * motion;
  pumpkinLeft.userData.glow.intensity = 1.7 + Math.sin(time * 4.8) * 0.24;
  pumpkinRight.rotation.y = 0.22 + Math.cos(time * 0.45) * 0.14 * motion + pointer.x * 0.08;
  pumpkinRight.position.y = -1.65 + Math.cos(time * 0.85) * 0.06 * motion;
  pumpkinRight.userData.glow.intensity = 1.5 + Math.cos(time * 5.1) * 0.2;

  vampire.position.y = -0.04 + Math.sin(time * 1.05 + 0.8) * 0.10 * motion + pointer.y * 0.055;
  vampire.rotation.y = -0.10 + Math.sin(time * 0.7) * 0.07 * motion + pointer.x * 0.09;
  vampire.rotation.z = Math.sin(time * 0.9) * 0.022 * motion;
  halo.rotation.z = -0.32 + Math.sin(time * 0.18) * 0.04 * motion;
  particles.rotation.y = time * 0.018 * motion;
  particles.rotation.x = time * 0.009 * motion;

  camera.position.x += (pointer.x * 0.18 - camera.position.x) * 0.018;
  camera.position.y += (pointer.y * 0.10 - camera.position.y) * 0.018;
  camera.lookAt(0, 0, 0);
  renderer.render(scene, camera);
});

window.addEventListener('pagehide', () => {
  observer.disconnect();
  resizeObserver.disconnect();
  mount.removeEventListener('pointermove', onPointerMove);
  renderer.setAnimationLoop(null);
  renderer.dispose();
  scene.traverse((object) => {
    if (object.geometry) object.geometry.dispose();
    if (object.material) {
      const materials = Array.isArray(object.material) ? object.material : [object.material];
      materials.forEach((material) => material.dispose());
    }
  });
});
