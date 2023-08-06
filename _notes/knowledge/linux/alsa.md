---
title: ALSA - Advanced Linux Sound Architecture
---

- [1. Overview](#1-overview)
  - [1.1. Pulse Code Modulation (PCM)](#11-pulse-code-modulation-pcm)
  - [1.2. Master](#12-master)
- [2. Control Interface](#2-control-interface)
  - [2.1. Card structure](#21-card-structure)

## 1. Overview
ALSA is one of the Linux kernel frameworks. It provides an API to develop sound card device drivers. It provides an API to control the sound card configuration (volume etc.) and to perform all type of mixing and sending digitial audio data to and from the sound card. It provides standarized and unified abstraction for implementing lower-level parts of the driver (e.g. USB control communication) to control certain parameters of the sound card (volume, ).

ALSA can operate on different levels of abstraction. In the kernel, there is a couple of sources of data for an ALSA driver, e.g. PCM or Master.

The `snd_` at the beginning of every ALSA API function and structure name stands for `sound`. A lot of defined constats names starts with `SNDRV` what supposedly mean `sound revolution` and indicates ALSA-API-related things.

### 1.1. Pulse Code Modulation (PCM)
PCM device refers to a virtual representation of an audio input or output channel of a sound card. These virtual devices in ALSA handle the conversion between digital audio data and analog audio signals. They provide an interface for audio data playback and capture, facilitating communication between audio applications and the sound card hardware. PCM devices in ALSA can be classified into two main types:

- Capture PCM Devices: These devices represent audio input channels, enabling applications to receive audio data from the sound card.
- Playback PCM Devices: These devices represent audio output channels, allowing applications to send audio data to the sound card for playback.

```bash
aplay -l                        # Show all available PCMs
```

### 1.2. Master
It controls the overall volume level (master) of the audio playback in the entire sound system, affecting the volume of all PCM devices simultaneously. It is a global volume control for the entire sound system.

## 2. Control Interface

### 2.1. Card structure
`snd_card` structure represents every sound card in the ALSA subsystem.
