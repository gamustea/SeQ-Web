# SeQ Landing Page - Design Specification

## Project Context
SeQ is a professional security operations platform with two main modules:
- **Sentinel**: REST API for vulnerability scanning (operational)
- **Acheron**: Encrypted secrets management via Vaults (in development)

## Hero Section (Video-First)
- **Style**: Full-viewport cinematic video background
- **Video Concept**: Abstract digital security visualization - flowing data streams, network nodes connecting, encryption patterns, matrix-style digital rain with green/emerald tones
- **Typography**: Massive display type "SeQ" with subtitle "Security Operations Platform"
- **CTA**: Gradient button linking to GitHub repository

## Color Palette (NO BLUE/PURPLE - Using Cyberpunk Green)
| Role | Color | Hex |
|------|-------|-----|
| Background Primary | Deep Black | #0A0A0A |
| Background Secondary | Dark Charcoal | #141414 |
| Surface | Obsidian | #1A1A1A |
| Accent Primary | Neon Emerald | #00FF88 |
| Accent Secondary | Electric Cyan | #00E5CC |
| Text Primary | Pure White | #FFFFFF |
| Text Secondary | Silver Grey | #A0A0A0 |
| Status Operational | Emerald Green | #22C55E |
| Status Development | Amber | #F59E0B |
| Danger/Alert | Crimson | #EF4444 |

## Typography
- **Display**: Inter or Space Grotesk (900 weight, 4-6rem)
- **Headlines**: Inter Semi-Bold (600 weight, 2-3rem)
- **Body**: Inter Regular (400 weight, 1rem)
- **Code**: JetBrains Mono or Fira Code

## Layout & Sections
1. **Hero**: 100vh video background, centered content, floating particles
2. **Modules Overview**: Two-card split layout (Sentinel vs Acheron)
3. **Scanning Features**: 3-column grid with icons (Nmap, Nikto, OpenVAS)
4. **Tech Stack**: Horizontal scrolling or grid showcase
5. **API Examples**: Code blocks with syntax highlighting
6. **Getting Started**: Installation steps with terminal styling
7. **Footer**: Minimal with GitHub link

## Motion Design
- Subtle fade-in animations on scroll (IntersectionObserver)
- Glowing hover effects on interactive elements
- Typing animation for code snippets
- Pulsing status indicators

## Visual Elements
- Glassmorphism cards with blur backdrop
- Gradient borders (emerald to cyan)
- Security icons (SVG): shields, locks, terminal, radar
- Circuit board patterns as subtle backgrounds
- Code terminal styling for examples

## Asset Protocol
- Hero Video: 1080p, 6-10 seconds loop, cinematic security visualization
- All icons: Inline SVG for crisp rendering
- No external CDN dependencies except Google Fonts

## Language
- All content in Spanish (matching README)
