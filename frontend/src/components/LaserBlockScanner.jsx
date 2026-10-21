import { useEffect, useRef } from 'react';

// Package definitions for incoming streaming blocks
const STREAM_PACKAGES = [
  { name: 'express', version: '4.19.2', isMalicious: false, type: 'cyan' },
  { name: 'lodahs', version: '0.7.21', isMalicious: true, attack: 'Typosquatting lodash', type: 'pink-radiant' },
  { name: 'react', version: '18.3.1', isMalicious: false, type: 'pink-radiant' },
  { name: 'axios', version: '1.7.2', isMalicious: false, type: 'emerald' },
  { name: 'fast-malware', version: '1.0.0', isMalicious: true, attack: 'RCE Shell Payload', type: 'pink-radiant' },
  { name: 'cookie', version: '0.6.0', isMalicious: false, type: 'yellow' },
  { name: 'install-exec', version: '0.2.1', isMalicious: true, attack: 'Compromised Hook Script', type: 'pink-radiant' },
  { name: 'body-parser', version: '1.20.2', isMalicious: false, type: 'white' },
  { name: 'requests-fake', version: '2.31.0', isMalicious: true, attack: 'Token Exfiltration', type: 'pink-radiant' },
  { name: 'chalk', version: '5.3.0', isMalicious: false, type: 'yellow' },
  { name: 'typescript', version: '5.4.5', isMalicious: false, type: 'white' },
  { name: 'crypto-miner', version: '0.9.1', isMalicious: true, attack: 'Background Miner Payload', type: 'pink-radiant' },
  { name: 'next', version: '14.2.3', isMalicious: false, type: 'white' },
  { name: 'lodash', version: '4.17.21', isMalicious: false, type: 'emerald' },
];

export default function LaserBlockScanner({ onStatsUpdate }) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d');
    let animId;
    let width = 0;
    let height = 0;
    let dpr = window.devicePixelRatio || 1;

    // Laser position: comfortable clearance for up to 14 blocks
    const getLaserX = () => Math.max(Math.round(width * 0.64), 880);

    // Bigger squares and grid as requested
    const SQUARE_SIZE = 55;
    const GAP = 5;
    const LANE_STEP = 62; // Vertical row step
    const GRID_LINE_STEP = 58; // Background grid line spacing

    // Exact 10 row block counts (final 10th row has 13 boxes):
    // [12, 11, 14, 7, 10, 13, 11, 14, 10, 13]
    const USER_ROW_BLOCK_COUNTS = [12, 11, 14, 7, 10, 13, 11, 14, 10, 13];

    // Calculate start position (from the very starting at x = 20) and number of slots
    const getRowSlotConfig = () => {
      const laserX = getLaserX();
      const startX = 20; // Starting from the leftmost edge
      const safeLaserBoundary = laserX - 22; // Strict boundary: 22px before laser line
      const slotStride = SQUARE_SIZE + GAP;
      const availableWidth = safeLaserBoundary - startX;
      const maxSlots = Math.max(1, Math.floor(availableWidth / slotStride));
      return { startX, maxSlots, slotStride, safeLaserBoundary };
    };

    // State tracking
    let incomingBlocks = [];
    let pixelShards = []; // Square pixel fragments on elimination
    let rowQueues = {};   // { [laneY]: Array<SettledBlock> }
    let spawnTimer = 0;
    let pkgIdx = 0;
    let laserFlareTime = 0;

    // Generate exactly 10 horizontal lanes corresponding to USER_ROW_BLOCK_COUNTS
    const getLanes = () => {
      const lanes = [];
      const startY = 90; // Red gap removed: 2-3px below 64px header
      for (let i = 0; i < USER_ROW_BLOCK_COUNTS.length; i++) {
        lanes.push(startY + i * LANE_STEP);
      }
      return lanes;
    };

    // Pre-populate rows starting from x = 20 with user's exact counts:
    // 1st: 11, 2nd: 10, 3rd: 13, 4th: 6, 5th: 9, 6th: 12, 7th: 10, 8th: 13, 9th: 9, 10th: 5, 11th: 11
    const initRowQueues = () => {
      rowQueues = {};
      const lanes = getLanes();
      const palette = ['pink-radiant', 'cyan', 'yellow', 'emerald', 'white', 'translucent-grey', 'dark-stepped'];

      // Non-repeating pseudorandom color selector so starting boxes have unique random colors
      const getBoxType = (rowIdx, slotIdx) => {
        const hash = Math.floor(Math.abs(Math.sin((rowIdx + 1) * 12.9898 + (slotIdx + 1) * 78.233) * 43758.5453));
        return palette[hash % palette.length];
      };

      const { startX, maxSlots, slotStride } = getRowSlotConfig();

      lanes.forEach((laneY, lIdx) => {
        rowQueues[laneY] = [];

        // Exact box counts specified by user, last rendered row is ALWAYS 13 boxes
        const isLastRow = (lIdx === lanes.length - 1);
        const requestedCount = isLastRow ? 13 : USER_ROW_BLOCK_COUNTS[lIdx % USER_ROW_BLOCK_COUNTS.length];
        const rowCapacity = Math.max(1, Math.min(maxSlots, requestedCount));

        for (let s = 0; s < rowCapacity; s++) {
          const x = startX + s * slotStride;
          const type = getBoxType(lIdx, s);
          rowQueues[laneY].push({
            x,
            targetX: x,
            y: laneY,
            size: SQUARE_SIZE,
            type,
            name: null,
            alpha: type === 'translucent-grey' ? 0.65 : 0.95,
            settled: true,
          });
        }
      });
    };

    // Handle high-DPI retina display resize
    const resize = () => {
      width = container.clientWidth || window.innerWidth;
      height = container.clientHeight || window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      initRowQueues();
    };

    resize();
    window.addEventListener('resize', resize);
    const layoutTimer = setTimeout(resize, 200);

    // Spawn an incoming block moving in a specific horizontal lane
    const spawnBlock = () => {
      const lanes = getLanes();
      const laneY = lanes[Math.floor(Math.random() * lanes.length)];
      const pkg = STREAM_PACKAGES[pkgIdx % STREAM_PACKAGES.length];
      pkgIdx++;

      incomingBlocks.push({
        id: Math.random(),
        pkg,
        x: width + 40,
        y: laneY,
        laneY,
        size: SQUARE_SIZE,
        speed: 2.5 + Math.random() * 0.4,
        state: 'approaching', // 'approaching' | 'vaporizing' | 'settling'
        type: pkg.type,
        isMalicious: pkg.isMalicious,
        name: pkg.name,
        zapProgress: 0,
        targetX: 0,
      });
    };

    // Spawns square pixel fragments (matching Image 2 pixel shards!)
    const spawnSquareShards = (x, y) => {
      const shardCount = 22;
      for (let i = 0; i < shardCount; i++) {
        const angle = Math.random() * Math.PI * 2;
        const speed = 2.0 + Math.random() * 5.5;
        pixelShards.push({
          x: x + SQUARE_SIZE / 2,
          y: y + SQUARE_SIZE / 2,
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed,
          size: 5 + Math.random() * 5, // Square debris
          color: Math.random() > 0.4 ? '#FF2E93' : '#EF4444',
          alpha: 1,
          decay: 0.02 + Math.random() * 0.025,
        });
      }
    };

    // Helper: Draws crisp pixel square matching Image 2 with larger 46px size
    const drawPixelSquare = (x, y, size, type, label, isMalicious, isZapping, zapProgress, alpha = 1) => {
      ctx.save();
      ctx.globalAlpha = alpha;

      if (isZapping) {
        // Exploding red threat block
        ctx.globalAlpha = Math.max(0, 1 - zapProgress);
        ctx.shadowColor = '#FF2E93';
        ctx.shadowBlur = 24;
        ctx.fillStyle = '#EF4444';
        ctx.fillRect(x, y, size, size);

        // White-hot shock border
        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = 2;
        ctx.strokeRect(x, y, size, size);

        // Warning Label
        ctx.font = 'bold 11px "JetBrains Mono", monospace';
        ctx.fillStyle = '#FF2E93';
        ctx.fillText('⚡ BLOCKED', x - 4, y - 8);
      } else if (type === 'pink-radiant') {
        // Exact Image 2 Radiant Hot-Pink/Magenta Square with Diagonal Sheen
        const grad = ctx.createLinearGradient(x, y, x + size, y + size);
        grad.addColorStop(0, '#FF2E93');
        grad.addColorStop(0.5, '#D946EF');
        grad.addColorStop(1, '#FF60B4');

        ctx.shadowColor = 'rgba(255, 46, 147, 0.65)';
        ctx.shadowBlur = 14;
        ctx.fillStyle = grad;
        ctx.fillRect(x, y, size, size);

        // Diagonal Specular Gloss Line (From Image 2)
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.55)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(x + 4, y + 4);
        ctx.lineTo(x + size - 4, y + size - 4);
        ctx.stroke();

        // 1px crisp outer stroke
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.35)';
        ctx.strokeRect(x, y, size, size);
      } else if (type === 'yellow') {
        // Image 2 Sharp Solid Yellow Square
        ctx.shadowColor = 'rgba(255, 230, 0, 0.45)';
        ctx.shadowBlur = 10;
        ctx.fillStyle = '#FFE600';
        ctx.fillRect(x, y, size, size);

        ctx.strokeStyle = 'rgba(0, 0, 0, 0.2)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, size, size);
      } else if (type === 'white') {
        // Image 2 Crisp Pure White Square
        ctx.shadowColor = 'rgba(255, 255, 255, 0.35)';
        ctx.shadowBlur = 10;
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(x, y, size, size);

        ctx.strokeStyle = 'rgba(180, 180, 200, 0.3)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, size, size);
      } else if (type === 'translucent-grey') {
        // Image 2 Semi-Transparent Glass Tile
        ctx.fillStyle = 'rgba(255, 255, 255, 0.09)';
        ctx.fillRect(x, y, size, size);

        ctx.strokeStyle = 'rgba(255, 255, 255, 0.16)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, size, size);
      } else if (type === 'dark-stepped') {
        // Dark Stepped Mosaic Tile
        ctx.fillStyle = 'rgba(42, 35, 60, 0.7)';
        ctx.fillRect(x, y, size, size);

        ctx.strokeStyle = 'rgba(90, 75, 120, 0.4)';
        ctx.lineWidth = 1;
        ctx.strokeRect(x, y, size, size);
      } else if (type === 'cyan') {
        ctx.shadowColor = 'rgba(56, 189, 248, 0.5)';
        ctx.shadowBlur = 10;
        ctx.fillStyle = '#38BDF8';
        ctx.fillRect(x, y, size, size);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.strokeRect(x, y, size, size);
      } else if (type === 'emerald') {
        ctx.shadowColor = 'rgba(52, 211, 153, 0.5)';
        ctx.shadowBlur = 10;
        ctx.fillStyle = '#34D399';
        ctx.fillRect(x, y, size, size);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
        ctx.strokeRect(x, y, size, size);
      }

      // Monospace Package Label
      if (label && !isZapping) {
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.fillStyle = isMalicious ? '#FF2E93' : '#CBD5E1';
        ctx.fillText(label, x - 2, y + size + 14);
      }

      ctx.restore();
    };

    let lastTime = performance.now();

    // ── Main 60 FPS Infinite Animation Loop ──────────────────────────
    const loop = (now) => {
      const dt = now - lastTime;
      lastTime = now;

      const laserX = getLaserX();
      const lanes = getLanes();

      // Clear with deep obsidian purple background
      ctx.fillStyle = '#12101B';
      ctx.fillRect(0, 0, width, height);

      // 1. Digital coordinate matrix grid lines
      ctx.strokeStyle = 'rgba(42, 34, 62, 0.45)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += GRID_LINE_STEP) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += GRID_LINE_STEP) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 2. Spawn incoming package blocks periodically
      spawnTimer += dt;
      if (spawnTimer > 1100) {
        spawnTimer = 0;
        spawnBlock();
      }

      // 3. Draw Settled Blocks in Each Row
      lanes.forEach((laneY) => {
        const queue = rowQueues[laneY] || [];

        for (let i = queue.length - 1; i >= 0; i--) {
          const b = queue[i];
          b.y = laneY; // Dynamically follow laneY so position shifts immediately reflect

          // Smoothly slide towards target slot if shifted
          if (b.x !== b.targetX) {
            b.x += (b.targetX - b.x) * 0.12;
          }

          // Safety clamp: ensure NO settled block ever crosses or touches the laser line
          const { safeLaserBoundary } = getRowSlotConfig();
          if (b.x + b.size > safeLaserBoundary) {
            b.x = safeLaserBoundary - b.size;
            b.targetX = b.x;
          }

          // If block is fading out (because row reached its capacity and a new block entered)
          if (b.fading) {
            b.alpha -= 0.045;
            b.x -= 2.5; // Smoothly slide away to left
            if (b.alpha <= 0) {
              queue.splice(i, 1);
              continue;
            }
          }

          drawPixelSquare(b.x, b.y, b.size, b.type, null, false, false, 0, b.alpha);
        }
      });

      // 4. Laser Gate
      const isZapping = laserFlareTime > 0;
      laserFlareTime = Math.max(0, laserFlareTime - dt);

      const laserTopY = 84;
      const laserBottomY = Math.max(height - 18, (lanes[lanes.length - 1] || 660) + SQUARE_SIZE + 19);

      // Core Laser Line (Sharp & clean without shadow effect)
      ctx.save();
      ctx.strokeStyle = isZapping ? '#FF2E93' : '#38BDF8';
      ctx.lineWidth = isZapping ? 3.5 : 2;
      ctx.beginPath();
      ctx.moveTo(laserX, laserTopY);
      ctx.lineTo(laserX, laserBottomY);
      ctx.stroke();
      ctx.restore();

      // Top and bottom emitter nodes
      const emitterColor = isZapping ? '#FF2E93' : '#38BDF8';
      ctx.fillStyle = emitterColor;
      ctx.beginPath();
      ctx.arc(laserX, laserTopY, isZapping ? 7 : 5, 0, Math.PI * 2);
      ctx.arc(laserX, laserBottomY, isZapping ? 7 : 5, 0, Math.PI * 2);
      ctx.fill();

      // Laser Gate Header Badge (2-3px below 64px header at y = 74)
      ctx.font = 'bold 10px "JetBrains Mono", monospace';
      ctx.fillStyle = isZapping ? '#FF2E93' : '#38BDF8';
      ctx.fillText(isZapping ? '⚡ LASER GATE: INTERCEPTING THREAT' : '◈ LASER POLICY GATE · FAIL-CLOSED', laserX - 95, 74);

      // 5. Update and Draw Incoming Blocks
      for (let i = incomingBlocks.length - 1; i >= 0; i--) {
        const b = incomingBlocks[i];

        if (b.state === 'approaching') {
          b.x -= b.speed;

          // Check if block reached the laser line
          if (b.x <= laserX + 4) {
            if (b.isMalicious) {
              // Threat detected! Laser line flares red & vaporizes the block
              b.state = 'vaporizing';
              laserFlareTime = 420;

              spawnSquareShards(b.x, b.y);
              onStatsUpdate?.({ blocked: 1, pkg: b.pkg });
            } else {
              // Safe package! Remains in the SAME ROW `laneY` and settles on the left
              b.state = 'settling';

              const laneY = b.laneY;
              const lIdx = lanes.indexOf(laneY) >= 0 ? lanes.indexOf(laneY) : 0;
              if (!rowQueues[laneY]) rowQueues[laneY] = [];
              const queue = rowQueues[laneY];

              const { startX, maxSlots, slotStride, safeLaserBoundary: boundary } = getRowSlotConfig();
              const isLastRow = (lIdx === lanes.length - 1);
              const requestedCount = isLastRow ? 13 : USER_ROW_BLOCK_COUNTS[lIdx % USER_ROW_BLOCK_COUNTS.length];
              const rowCapacity = Math.max(1, Math.min(maxSlots, requestedCount));

              b.x = boundary - b.size; // Immediately inside the laser boundary, never outside

              // If the row queue already reached this row's capacity:
              if (queue.length >= rowCapacity) {
                // Mark oldest block to smoothly fade away to left (into the text blur)
                const oldest = queue[0];
                oldest.fading = true;

                // Shift remaining blocks in this row left by 1 slot
                for (let q = 1; q < queue.length; q++) {
                  queue[q].targetX = startX + (q - 1) * slotStride;
                }

                // Append new block into the rightmost available slot of this row
                b.targetX = startX + (rowCapacity - 1) * slotStride;
              } else {
                // Append new block into the next slot
                b.targetX = startX + queue.length * slotStride;
              }

              // Strict clamp: never allow block outside laser boundary
              if (b.targetX + b.size > boundary) {
                b.targetX = boundary - b.size;
              }

              onStatsUpdate?.({ verified: 1, pkg: b.pkg });
            }
          }
        } else if (b.state === 'vaporizing') {
          b.zapProgress += 0.085;
          b.x += (Math.random() - 0.5) * 4; // High-frequency vibration

          // Electric zap bolt from laser line to malicious block
          ctx.save();
          ctx.strokeStyle = '#FFFFFF';
          ctx.lineWidth = 2.5;
          ctx.shadowColor = '#FF2E93';
          ctx.shadowBlur = 10;
          ctx.beginPath();
          ctx.moveTo(laserX, b.y + b.size / 2);
          ctx.lineTo(b.x + b.size / 2, b.y + b.size / 2);
          ctx.stroke();
          ctx.restore();

          if (b.zapProgress >= 1) {
            // Completely vaporized and eliminated!
            incomingBlocks.splice(i, 1);
            continue;
          }
        } else if (b.state === 'settling') {
          // Smooth glide horizontally in the SAME ROW `b.laneY` to targetX
          b.x += (b.targetX - b.x) * 0.08;

          // When close enough, commit to settled queue in this row
          if (Math.abs(b.x - b.targetX) < 2.5) {
            b.x = b.targetX;
            if (!rowQueues[b.laneY]) rowQueues[b.laneY] = [];
            rowQueues[b.laneY].push({
              x: b.targetX,
              targetX: b.targetX,
              y: b.laneY,
              size: b.size,
              type: b.type,
              name: null,
              alpha: 0.95,
              settled: true,
            });

            incomingBlocks.splice(i, 1);
            continue;
          }
        }

        // Draw the block with Image 2 square tile quality
        drawPixelSquare(
          b.x,
          b.y,
          b.size,
          b.type,
          b.name,
          b.isMalicious,
          b.state === 'vaporizing',
          b.zapProgress
        );
      }

      // 6. Draw Square Pixel Shards (Explosion Particles)
      for (let i = pixelShards.length - 1; i >= 0; i--) {
        const p = pixelShards[i];
        p.x += p.vx;
        p.y += p.vy;
        p.alpha -= p.decay;

        if (p.alpha <= 0) {
          pixelShards.splice(i, 1);
          continue;
        }

        ctx.save();
        ctx.globalAlpha = Math.max(0, p.alpha);
        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 8;
        // Crisp square pixel debris
        ctx.fillRect(p.x, p.y, p.size, p.size);
        ctx.restore();
      }

      // 7. Right Side Stream Label
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.fillStyle = '#64748B';
      ctx.fillText('INCOMING DEPENDENCY PIPELINE →', width - 210, height - 20);

      animId = requestAnimationFrame(loop);
    };

    animId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
      clearTimeout(layoutTimer);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="absolute inset-0 w-full h-full pointer-events-none select-none z-0 overflow-hidden"
    >
      <canvas
        ref={canvasRef}
        className="w-full h-full block"
      />
    </div>
  );
}

if (import.meta.hot) {
  import.meta.hot.decline();
}
