// The Earth behind the sign-in page, as a camera on a satellite sees it: the planet below, its curved edge and a thin
// band of air against space. The satellite circles on a tilted orbit, faster than a real one so the motion shows, and
// the camera looks north, so east is on the right. Day and night follow the real clock: the lit side is where it is
// daytime now. Requests arc between cities: green ones arrive, red ones are refused on the way.
// Decoration only: nothing here comes from the lab or from any other server, and the page says so.
import {COAST} from './globedata.js';

const MINT = '#8fd9b6';
const REFUSED = '#ff8f87';
const RAD = Math.PI / 180;
const ALT = 1.45; // the satellite's distance from the centre, in Earth radii: about 2,900 km up
const LOOK = 37 * RAD; // the camera leans from straight down towards the northern horizon
const ROLL = -7 * RAD; // and is turned a little, so the horizon slopes
const HALF_FOV = 30 * RAD; // half the camera's view, top to bottom
const INC = 40 * RAD; // the orbit's tilt to the equator
const ORBIT = 1.1 * RAD; // per second along the orbit; a real one at this height takes about two hours
const DRIFT = ORBIT / 12; // the Earth turning under the orbit moves each pass west
const AIR = 0.022; // the visible band of air, in Earth radii
const STEP = 3; // the sphere is shaded on a grid of 3 x 3 screen pixels and smoothed
const FRAME = 1000 / 24;
const ARCS = 9;
const GRID_W = 2048;
const GRID_H = 1024;
const CITIES = [[28.6, 77.2], [19.1, 72.9], [12.97, 77.6], [22.6, 88.4], [1.35, 103.8], [35.7, 139.7], [31.2, 121.5], [25.2, 55.3],
  [51.5, -0.1], [50.1, 8.7], [-1.3, 36.8], [6.5, 3.4], [-33.9, 151.2], [-23.6, -46.6], [40.7, -74], [37.8, -122.4], [55.8, 37.6]];

// colours of the ground, lit and unlit, and of the air
const OCEAN_DAY = [34, 98, 88];
const OCEAN_NIGHT = [16, 48, 42];
const LAND_DAY = [140, 194, 166];
const LAND_NIGHT = [44, 80, 66];
const HAZE = [170, 226, 204];

function bytes(text) {
  const raw = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

/** Latitude and longitude in degrees to a point on the unit sphere. North is +y; longitude 0 is +x, 90 E is +z. */
function unit(lat, lon) {
  const c = Math.cos(lat * RAD);
  return [c * Math.cos(lon * RAD), Math.sin(lat * RAD), c * Math.sin(lon * RAD)];
}

/**
 * Where the land is, as a map of the world 2048 x 1024 pixels across: the coast shapes are filled on a hidden canvas.
 * Shapes cut at the 180th meridian are made continuous first and drawn once more on each side; Antarctica, which goes
 * all the way round, is closed along the South Pole.
 */
function landGrid() {
  const map = document.createElement('canvas');
  map.width = GRID_W;
  map.height = GRID_H;
  const m = map.getContext('2d', {willReadFrequently: true});
  if (!m) return new Uint8Array(GRID_W * GRID_H);
  const b = bytes(COAST);
  const v = new Int16Array(b.buffer, b.byteOffset, Math.floor(b.length / 2));
  const kx = GRID_W / 360;
  const ky = GRID_H / 180;
  m.fillStyle = '#fff';
  let ring = [];
  const draw = () => {
    if (ring.length < 3) return;
    const span = ring[ring.length - 1][0] - ring[0][0];
    if (Math.abs(span) > 300) {
      const pole = ring.reduce((t, p) => t + p[1], 0) < 0 ? -90 : 90;
      ring.push([ring[ring.length - 1][0], pole], [ring[0][0], pole]);
    }
    for (const shift of [-360, 0, 360]) {
      m.beginPath();
      ring.forEach(([lon, lat], i) => {
        const x = (lon + shift + 180) * kx;
        const y = (90 - lat) * ky;
        if (i) m.lineTo(x, y);
        else m.moveTo(x, y);
      });
      m.closePath();
      m.fill();
    }
  };
  for (let i = 0; i + 1 < v.length; i += 2) {
    if (v[i] === 32767) {
      draw();
      ring = [];
      continue;
    }
    let lon = v[i] / 100;
    if (ring.length) {
      const before = ring[ring.length - 1][0];
      while (lon - before > 180) lon -= 360;
      while (lon - before < -180) lon += 360;
    }
    ring.push([lon, v[i + 1] / 100]);
  }
  draw();
  const px = m.getImageData(0, 0, GRID_W, GRID_H).data;
  const land = new Uint8Array(GRID_W * GRID_H);
  for (let i = 0; i < land.length; i++) land[i] = px[i * 4 + 3];
  return land;
}

function coastLines() {
  const b = bytes(COAST);
  const v = new Int16Array(b.buffer, b.byteOffset, Math.floor(b.length / 2));
  const lines = [];
  let line = [];
  for (let i = 0; i + 1 < v.length; i += 2) {
    if (v[i] === 32767) {
      if (line.length) lines.push(Float32Array.from(line));
      line = [];
    } else {
      line.push(...unit(v[i + 1] / 100, v[i] / 100));
    }
  }
  return lines;
}

/** Where the Sun is overhead now, as a unit vector. Close enough for a picture: within a degree or so. */
function sunNow() {
  const now = new Date();
  const day = (now - Date.UTC(now.getUTCFullYear(), 0, 0)) / 864e5;
  const declination = -23.44 * Math.cos((2 * Math.PI * (day + 10)) / 365);
  const hours = now.getUTCHours() + now.getUTCMinutes() / 60 + now.getUTCSeconds() / 3600;
  return unit(declination, (12 - hours) * 15);
}

function newArc() {
  const a = Math.floor(Math.random() * CITIES.length);
  let b = Math.floor(Math.random() * CITIES.length);
  if (a === b) b = (b + 1) % CITIES.length;
  return {from: unit(...CITIES[a]), to: unit(...CITIES[b]), t: Math.random() * -0.6, ok: Math.random() > 0.28, speed: 0.22 + Math.random() * 0.14};
}

/** A point along the way from a to b, lifted off the surface in the middle of the journey. */
function along(a, b, t) {
  const x = a[0] + (b[0] - a[0]) * t;
  const y = a[1] + (b[1] - a[1]) * t;
  const z = a[2] + (b[2] - a[2]) * t;
  const len = Math.hypot(x, y, z) || 1;
  const lift = (1 + 0.07 * Math.sin(Math.PI * t)) / len;
  return [x * lift, y * lift, z * lift];
}

const smooth = (a, b, x) => {
  const t = Math.min(1, Math.max(0, (x - a) / (b - a)));
  return t * t * (3 - 2 * t);
};

/** Starts the picture on canvas; returns the function that stops it. */
export function startGlobe(canvas) {
  const c = canvas.getContext('2d');
  const shade = document.createElement('canvas');
  const s2 = shade.getContext('2d');
  if (!c || !s2) return () => {};
  const grid = landGrid();
  const coast = coastLines();
  const arcs = Array.from({length: ARCS}, newArc);
  const stars = Array.from({length: 160}, () => [Math.random(), Math.random() * 0.75, 0.3 + Math.random() * 0.9, Math.random() * 6.3]);
  const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const scale = Math.min(window.devicePixelRatio || 1, 2);
  let width = 0;
  let height = 0;
  let image = null;
  let frame = 0;
  let last = 0;
  let clock = 0;

  // the orbit starts with the satellite south of India, heading east, so the camera looks north over India
  const startLat = 3 * RAD;
  const u0 = Math.asin(Math.sin(startLat) / Math.sin(INC));
  const node0 = 78 * RAD - Math.atan2(Math.cos(INC) * Math.sin(u0), Math.cos(u0));

  const resize = () => {
    width = canvas.clientWidth || 1280;
    height = canvas.clientHeight || 800;
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    shade.width = Math.ceil(width / STEP);
    shade.height = Math.ceil(height / STEP);
    image = s2.createImageData(shade.width, shade.height);
  };

  const draw = (now) => {
    frame = requestAnimationFrame(draw);
    const gap = now - last;
    if (gap < FRAME && !still) return;
    last = now;
    clock += Math.min(gap, 100) / 1000;

    // where the satellite is: over s, moving along v; n points to the left of the track (north on the way east)
    const u = u0 + ORBIT * clock;
    const node = node0 - DRIFT * clock;
    const N = [Math.cos(node), 0, Math.sin(node)];
    const E = [-Math.sin(node), 0, Math.cos(node)];
    const M = [E[0] * Math.cos(INC), Math.sin(INC), E[2] * Math.cos(INC)];
    const s = [N[0] * Math.cos(u) + M[0] * Math.sin(u), N[1] * Math.cos(u) + M[1] * Math.sin(u), N[2] * Math.cos(u) + M[2] * Math.sin(u)];
    const v = [-N[0] * Math.sin(u) + M[0] * Math.cos(u), -N[1] * Math.sin(u) + M[1] * Math.cos(u), -N[2] * Math.sin(u) + M[2] * Math.cos(u)];
    const n = [v[1] * s[2] - v[2] * s[1], v[2] * s[0] - v[0] * s[2], v[0] * s[1] - v[1] * s[0]];
    const cl = Math.cos(LOOK);
    const sl = Math.sin(LOOK);
    const look = [-s[0] * cl + n[0] * sl, -s[1] * cl + n[1] * sl, -s[2] * cl + n[2] * sl];
    const up0 = [s[0] * sl + n[0] * cl, s[1] * sl + n[1] * cl, s[2] * sl + n[2] * cl];
    const cr = Math.cos(ROLL);
    const sr = Math.sin(ROLL);
    const right = [v[0] * cr + up0[0] * sr, v[1] * cr + up0[1] * sr, v[2] * cr + up0[2] * sr];
    const up = [up0[0] * cr - v[0] * sr, up0[1] * cr - v[1] * sr, up0[2] * cr - v[2] * sr];
    const C = [s[0] * ALT, s[1] * ALT, s[2] * ALT];
    const c2 = ALT * ALT - 1;
    const f = height / 2 / Math.tan(HALF_FOV);
    const cx = width * 0.5;
    const cy = height * 0.5;
    const sun = sunNow();
    // how fast the distance of a ray from the centre changes per grid cell at the edge: used to smooth the edge
    const edgeRate = (ALT * Math.sqrt(1 - 1 / (ALT * ALT)) * STEP) / f;

    // the ground and the air, one ray per grid cell
    const bw = shade.width;
    const bh = shade.height;
    const px = image.data;
    for (let j = 0; j < bh; j++) {
      const sy = ((j + 0.5) * STEP - cy) / f;
      for (let i = 0; i < bw; i++) {
        const sx = ((i + 0.5) * STEP - cx) / f;
        let dx = look[0] + right[0] * sx - up[0] * sy;
        let dy = look[1] + right[1] * sx - up[1] * sy;
        let dz = look[2] + right[2] * sx - up[2] * sy;
        const inv = 1 / Math.sqrt(dx * dx + dy * dy + dz * dz);
        dx *= inv;
        dy *= inv;
        dz *= inv;
        const b = dx * C[0] + dy * C[1] + dz * C[2];
        const disc = b * b - c2;
        const o = (j * bw + i) * 4;
        const miss = b < 0 ? Math.sqrt(Math.max(0, ALT * ALT - b * b)) : 9;
        // the air: brightest at the edge of the planet, fading out into space
        const air = miss < 1 ? 1 : miss < 1 + AIR ? (1 - (miss - 1) / AIR) * (1 - (miss - 1) / AIR) : 0;
        let airAlpha = 0;
        if (air > 0) {
          const qx = C[0] - b * dx;
          const qy = C[1] - b * dy;
          const qz = C[2] - b * dz;
          airAlpha = 230 * air * (0.35 + 0.65 * smooth(-0.3, 0.3, (qx * sun[0] + qy * sun[1] + qz * sun[2]) / miss));
        }
        if (b < 0 && disc >= 0) {
          const cover = Math.min(1, 0.5 + (1 - miss) / edgeRate);
          const t = -b - Math.sqrt(disc);
          const x = C[0] + t * dx;
          const y = C[1] + t * dy;
          const z = C[2] + t * dz;
          const light = x * sun[0] + y * sun[1] + z * sun[2];
          const day = smooth(-0.12, 0.28, light);
          const bright = 0.78 + 0.22 * Math.max(0, light);
          const gx = (Math.atan2(z, x) / RAD + 180) * (GRID_W / 360) - 0.5;
          const gy = (90 - Math.asin(Math.max(-1, Math.min(1, y))) / RAD) * (GRID_H / 180) - 0.5;
          const x0 = Math.floor(gx);
          const y0 = Math.max(0, Math.min(GRID_H - 2, Math.floor(gy)));
          const fx = gx - x0;
          const fy = Math.max(0, Math.min(1, gy - y0));
          const a0 = ((x0 % GRID_W) + GRID_W) % GRID_W;
          const a1 = (a0 + 1) % GRID_W;
          const top = grid[y0 * GRID_W + a0] * (1 - fx) + grid[y0 * GRID_W + a1] * fx;
          const bottom = grid[(y0 + 1) * GRID_W + a0] * (1 - fx) + grid[(y0 + 1) * GRID_W + a1] * fx;
          const land = (top * (1 - fy) + bottom * fy) / 255;
          const facing = -(dx * x + dy * y + dz * z);
          const edge = 1 - Math.max(0, facing);
          const haze = edge * edge * edge * edge * (0.25 + 0.5 * day);
          for (let k = 0; k < 3; k++) {
            const lit = (OCEAN_DAY[k] * (1 - land) + LAND_DAY[k] * land) * bright;
            const dark = OCEAN_NIGHT[k] * (1 - land) + LAND_NIGHT[k] * land;
            const ground = dark + (lit - dark) * day;
            const seen = ground + (HAZE[k] - ground) * haze;
            px[o + k] = seen * cover + HAZE[k] * (1 - cover);
          }
          px[o + 3] = 255 * cover + airAlpha * (1 - cover);
        } else if (airAlpha > 0) {
          px[o] = HAZE[0];
          px[o + 1] = HAZE[1];
          px[o + 2] = HAZE[2];
          px[o + 3] = airAlpha;
        } else {
          px[o + 3] = 0;
        }
      }
    }
    s2.putImageData(image, 0, 0);

    c.setTransform(scale, 0, 0, scale, 0, 0);
    c.clearRect(0, 0, width, height);

    // stars
    c.fillStyle = '#e8f5ee';
    for (const [x, y, r, phase] of stars) {
      c.globalAlpha = 0.25 + 0.35 * (0.5 + 0.5 * Math.sin(phase + clock * 0.8));
      c.fillRect(x * width, y * height, r, r);
    }
    c.globalAlpha = 1;
    c.imageSmoothingEnabled = true;
    c.imageSmoothingQuality = 'high';
    c.drawImage(shade, 0, 0, bw * STEP, bh * STEP);

    // projecting a point: hidden behind the planet, or a screen position
    const out = [0, 0];
    const place = (q) => {
      const ex = q[0] - C[0];
      const ey = q[1] - C[1];
      const ez = q[2] - C[2];
      const z = ex * look[0] + ey * look[1] + ez * look[2];
      if (z <= 0.01) return false;
      out[0] = cx + (f * (ex * right[0] + ey * right[1] + ez * right[2])) / z;
      out[1] = cy - (f * (ex * up[0] + ey * up[1] + ez * up[2])) / z;
      return true;
    };
    const front = (x, y, z) => x * s[0] + y * s[1] + z * s[2] >= 1 / ALT;
    // a request is drawn only while the ground under it is in view, so none hangs in the sky past the horizon
    const clear = (q) => {
      const len = Math.hypot(q[0], q[1], q[2]);
      if ((q[0] * s[0] + q[1] * s[1] + q[2] * s[2]) / len < 1 / ALT + 0.03) return false;
      const ex = q[0] - C[0];
      const ey = q[1] - C[1];
      const ez = q[2] - C[2];
      const a = ex * ex + ey * ey + ez * ez;
      const b = 2 * (C[0] * ex + C[1] * ey + C[2] * ez);
      const disc = b * b - 4 * a * c2;
      if (disc < 0) return true;
      return (-b - Math.sqrt(disc)) / (2 * a) > 0.999;
    };

    // coasts
    c.strokeStyle = 'rgba(226, 246, 236, .5)';
    c.lineWidth = 0.9;
    c.beginPath();
    const q = [0, 0, 0];
    for (const line of coast) {
      let pen = false;
      for (let i = 0; i < line.length; i += 3) {
        q[0] = line[i];
        q[1] = line[i + 1];
        q[2] = line[i + 2];
        if (front(q[0], q[1], q[2]) && place(q)) {
          if (pen) c.lineTo(out[0], out[1]);
          else c.moveTo(out[0], out[1]);
          pen = true;
        } else {
          pen = false;
        }
      }
    }
    c.stroke();

    // city lights on the night side
    c.fillStyle = '#f5d06f';
    for (const [lat, lon] of CITIES) {
      const p = unit(lat, lon);
      const night = 1 - smooth(-0.15, 0.05, p[0] * sun[0] + p[1] * sun[1] + p[2] * sun[2]);
      if (night <= 0 || !front(p[0], p[1], p[2]) || !place(p)) continue;
      c.globalAlpha = 0.25 * night;
      c.beginPath();
      c.arc(out[0], out[1], 6, 0, Math.PI * 2);
      c.fill();
      c.globalAlpha = 0.9 * night;
      c.beginPath();
      c.arc(out[0], out[1], 1.8, 0, Math.PI * 2);
      c.fill();
    }
    c.globalAlpha = 1;

    // requests
    arcs.forEach((a, k) => {
      a.t += (a.speed * Math.min(gap, 100)) / 1000;
      const stop = a.ok ? 1 : 0.62;
      if (a.t > stop + 0.25) {
        arcs[k] = newArc();
        return;
      }
      if (a.t < 0) return;
      const head = Math.min(a.t, stop);
      const tail = Math.max(0, head - 0.3);
      const colour = a.ok ? MINT : REFUSED;
      c.strokeStyle = colour;
      c.lineWidth = 1.6;
      c.beginPath();
      let pen = false;
      for (let t = tail; t <= head; t += 0.02) {
        const p = along(a.from, a.to, t);
        if (clear(p) && place(p)) {
          if (pen) c.lineTo(out[0], out[1]);
          else c.moveTo(out[0], out[1]);
          pen = true;
        } else {
          pen = false;
        }
      }
      c.stroke();
      const p = along(a.from, a.to, head);
      if (clear(p) && place(p)) {
        c.fillStyle = colour;
        c.beginPath();
        c.arc(out[0], out[1], a.t > stop ? 2 + (a.t - stop) * 16 : 2.6, 0, Math.PI * 2);
        if (a.t > stop) {
          c.lineWidth = 1;
          c.stroke();
        } else {
          c.fill();
        }
      }
    });
    if (still) cancelAnimationFrame(frame);
  };

  resize();
  window.addEventListener('resize', resize);
  frame = requestAnimationFrame(draw);
  return () => {
    cancelAnimationFrame(frame);
    window.removeEventListener('resize', resize);
  };
}
