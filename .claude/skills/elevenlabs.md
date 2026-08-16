---
description: >
  ElevenLabs API skill — pronunciation dictionaries, request stitching, voice
  cloning (IVC), voice design, voice remixing, music composition plans, and
  music inpainting. Trigger on: "elevenlabs", "eleven labs", "tts",
  "text-to-speech", "pronunciation dictionary", "voice clone", "voice design",
  "voice remix", "music compose", "music inpainting", "request stitching",
  "PLS file", "IPA phoneme", "CMU phoneme", "composition plan".
---

# ElevenLabs API Skill

Reference for building with the ElevenLabs API. Covers pronunciation
dictionaries, request stitching, voice cloning, voice design, voice remixing,
music composition plans, and music inpainting.

Both Python (`elevenlabs` package) and TypeScript (`@elevenlabs/elevenlabs-js`
package) SDKs are supported. Default to whichever language the project uses; if
ambiguous, provide both.

---

## 1. Pronunciation Dictionaries

Customize how TTS pronounces specific words. Supports IPA and CMU alphabets.

**Model compatibility:** Phoneme tags only work with `eleven_flash_v2` and
`eleven_v3`. Other models skip phoneme tags — use alias tags instead. For
non-English IPA/CMU, use `eleven_v3`.

### PLS file format

PLS files are XML, case-sensitive. Include both cased variants if needed.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<lexicon version="1.0"
    xmlns="http://www.w3.org/2005/01/pronunciation-lexicon"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.w3.org/2005/01/pronunciation-lexicon
        http://www.w3.org/TR/2007/CR-pronunciation-lexicon-20071212/pls.xsd"
    alphabet="ipa" xml:lang="en-US">
<lexeme>
    <grapheme>tomato</grapheme>
    <phoneme>/tə'meɪtoʊ/</phoneme>
</lexeme>
<lexeme>
    <grapheme>Tomato</grapheme>
    <phoneme>/tə'meɪtoʊ/</phoneme>
</lexeme>
</lexicon>
```

### Create and use a dictionary — Python

```python
from elevenlabs.client import ElevenLabs
from elevenlabs.play import play, PronunciationDictionaryVersionLocator

elevenlabs = ElevenLabs()

with open("dictionary.pls", "rb") as f:
    pronunciation_dictionary = elevenlabs.pronunciation_dictionaries.create_from_file(
        file=f.read(), name="example"
    )

audio = elevenlabs.text_to_speech.convert(
    text="With the dictionary: tomato",
    voice_id="<VOICE_ID>",
    model_id="eleven_flash_v2",
    pronunciation_dictionary_locators=[
        PronunciationDictionaryVersionLocator(
            pronunciation_dictionary_id=pronunciation_dictionary.id,
            version_id=pronunciation_dictionary.version_id,
        )
    ],
)

play(audio)
```

### Create and use a dictionary — TypeScript

```typescript
import { ElevenLabsClient, play } from "@elevenlabs/elevenlabs-js";
import fs from "node:fs";

const elevenlabs = new ElevenLabsClient();

const pronunciationDictionary =
  await elevenlabs.pronunciationDictionaries.createFromFile({
    file: fs.createReadStream("dictionary.pls"),
  });

const audio = await elevenlabs.textToSpeech.convert("<VOICE_ID>", {
  text: "With the dictionary: tomato",
  modelId: "eleven_flash_v2",
  pronunciationDictionaryLocators: [
    {
      pronunciationDictionaryId: pronunciationDictionary.id,
      versionId: pronunciationDictionary.versionId,
    },
  ],
});

play(audio);
```

---

## 2. Request Stitching

Maintain voice prosody across multiple text chunks by passing previous request
IDs to subsequent calls.

**Not available for `eleven_v3`.**

Previous requests must have finished processing (stream fully consumed) before
their IDs can be used. Request IDs should be no older than two hours.

### Python

```python
from io import BytesIO
from elevenlabs.client import ElevenLabs
from elevenlabs.play import play

elevenlabs = ElevenLabs()

paragraphs = [
    "The advent of technology has transformed countless sectors...",
    "In recent years, educational technology has revolutionized...",
    "One of the primary benefits of technology in education is...",
]

request_ids = []
audio_buffers = []

for paragraph in paragraphs:
    with elevenlabs.text_to_speech.with_raw_response.convert(
        text=paragraph,
        voice_id="<VOICE_ID>",
        model_id="eleven_multilingual_v2",
        previous_request_ids=request_ids,
    ) as response:
        request_ids.append(response._response.headers.get("request-id"))
        audio_data = b"".join(chunk for chunk in response.data)
        audio_buffers.append(BytesIO(audio_data))

combined = BytesIO(b"".join(buf.getvalue() for buf in audio_buffers))
play(combined)
```

### TypeScript

```typescript
import { ElevenLabsClient, play } from "@elevenlabs/elevenlabs-js";
import { Readable } from "node:stream";

const elevenlabs = new ElevenLabsClient();

const paragraphs = [
  "The advent of technology has transformed countless sectors...",
  "In recent years, educational technology has revolutionized...",
  "One of the primary benefits of technology in education is...",
];

const requestIds: string[] = [];
const audioBuffers: Buffer[] = [];

for (const paragraph of paragraphs) {
  const response = await elevenlabs.textToSpeech
    .convert("<VOICE_ID>", {
      text: paragraph,
      modelId: "eleven_multilingual_v2",
      previousRequestIds: requestIds,
    })
    .withRawResponse();

  requestIds.push(response.rawResponse.headers.get("request-id") ?? "");

  const chunks: Buffer[] = [];
  for await (const chunk of response.data) {
    chunks.push(Buffer.from(chunk));
  }
  audioBuffers.push(Buffer.concat(chunks));
}

const combinedStream = Readable.from(Buffer.concat(audioBuffers));
play(combinedStream);
```

---

## 3. Instant Voice Cloning (IVC)

Clone a voice from audio samples. More samples = better quality.

### Python

```python
from elevenlabs.client import ElevenLabs
from io import BytesIO

elevenlabs = ElevenLabs()

voice = elevenlabs.voices.ivc.create(
    name="My Voice Clone",
    files=[BytesIO(open("/path/to/audio.mp3", "rb").read())],
)

print(voice.voice_id)
```

### TypeScript

```typescript
import { ElevenLabsClient } from "@elevenlabs/elevenlabs-js";
import fs from "node:fs";

const elevenlabs = new ElevenLabsClient();

const voice = await elevenlabs.voices.ivc.create({
  name: "My Voice Clone",
  files: [fs.createReadStream("/path/to/audio.mp3")],
});

console.log(voice.voiceId);
```

---

## 4. Voice Design

Generate a voice from a text description. Two-step process: generate previews,
then save the best one.

### Python

```python
from elevenlabs.client import ElevenLabs
from elevenlabs.play import play
import base64

elevenlabs = ElevenLabs()

# Step 1: generate previews
voices = elevenlabs.text_to_voice.design(
    model_id="eleven_multilingual_ttv_v2",
    voice_description="A deep, calm narrator with a British accent.",
    text="Sample text for the voice preview.",
)

for preview in voices.previews:
    audio_buffer = base64.b64decode(preview.audio_base_64)
    play(audio_buffer)

# Step 2: save to library
voice = elevenlabs.text_to_voice.create(
    voice_name="British Narrator",
    voice_description="Deep, calm British narrator.",
    generated_voice_id=voices.previews[0].generated_voice_id,
)

print(voice.voice_id)
```

### TypeScript

```typescript
import { ElevenLabsClient, play } from "@elevenlabs/elevenlabs-js";
import { Readable } from "node:stream";
import { Buffer } from "node:buffer";

const elevenlabs = new ElevenLabsClient();

// Step 1: generate previews
const { previews } = await elevenlabs.textToVoice.design({
  modelId: "eleven_multilingual_ttv_v2",
  voiceDescription: "A deep, calm narrator with a British accent.",
  text: "Sample text for the voice preview.",
});

for (const preview of previews) {
  const audioStream = Readable.from(
    Buffer.from(preview.audioBase64, "base64")
  );
  await play(audioStream);
}

// Step 2: save to library
const voice = await elevenlabs.textToVoice.create({
  voiceName: "British Narrator",
  voiceDescription: "Deep, calm British narrator.",
  generatedVoiceId: previews[0].generatedVoiceId,
});

console.log(voice.voiceId);
```

---

## 5. Voice Remixing

Remix an existing voice with a new prompt. Only works with designed voices, IVC,
PVC, and Voice Library voices with infinite notice periods.

### Python

```python
from elevenlabs.client import ElevenLabs
from elevenlabs.play import play
import base64

elevenlabs = ElevenLabs()

voices = elevenlabs.text_to_voice.remix(
    voice_id="<EXISTING_VOICE_ID>",
    voice_description="Use a higher pitch and change to a Boston accent.",
    text="Of course I'm a Bostonian, I've lived here all my life!",
)

for preview in voices.previews:
    audio_buffer = base64.b64decode(preview.audio_base_64)
    play(audio_buffer)

# Save the remixed voice
voice = elevenlabs.text_to_voice.create(
    voice_name="Bostonian",
    voice_description="A high pitched Bostonian accent.",
    generated_voice_id=voices.previews[0].generated_voice_id,
)

print(voice.voice_id)
```

### TypeScript

```typescript
import { ElevenLabsClient, play } from "@elevenlabs/elevenlabs-js";
import { Readable } from "node:stream";
import { Buffer } from "node:buffer";

const elevenlabs = new ElevenLabsClient();

const { previews } = await elevenlabs.textToVoice.remix("<EXISTING_VOICE_ID>", {
  voiceDescription: "Use a higher pitch and change to a Boston accent.",
  text: "Of course I'm a Bostonian, I've lived here all my life!",
});

for (const preview of previews) {
  const audioStream = Readable.from(
    Buffer.from(preview.audioBase64, "base64")
  );
  await play(audioStream);
}

const voice = await elevenlabs.textToVoice.create({
  voiceName: "Bostonian",
  voiceDescription: "A high pitched Bostonian accent.",
  generatedVoiceId: previews[0].generatedVoiceId,
});

console.log(voice.voiceId);
```

---

## 6. Music Composition Plans

Fine-grained control over music generation with `music_v2`. A plan is an
ordered list of up to 30 chunks, each defining a section with text, styles, and
duration.

**Text prompts and composition plans are mutually exclusive.**

### Chunk fields

| Field               | Type   | Description                                                                |
| ------------------- | ------ | -------------------------------------------------------------------------- |
| `text`              | string | `[Section Name]`, lyrics (`\n`-separated), inline cues in `{braces}`.     |
| `duration_ms`       | number | 3,000–120,000 ms.                                                         |
| `positive_styles`   | array  | Styles to include (max 50).                                               |
| `negative_styles`   | array  | Styles to avoid (max 50, default empty).                                  |
| `context_adherence` | string | `low`, `medium`, or `high` (default). Closeness to surrounding chunks.    |

### Lyrics format

- Section names in square brackets: `[Verse 1]`, `[Chorus]`
- Lyrics as plain text, newline-separated
- Phonetic sounds in parentheses: `(ooh)`, `(hmmm)`
- Inline directions in curly braces: `{guitar solo}`, `{instrumental break}`
- Broad characteristics (genre, instrumentation) go in `positive_styles`, not inline

### Style tips

- First chunk styles set the overall tone — use 6–7 styles minimum
- Be specific: `"warm acoustic guitar with light fingerpicking"` > `"guitar"`
- Use `negative_styles` liberally to prevent unwanted sounds
- Styles must be in English (lyrics can be any language)
- Copyrighted content in styles returns `bad_composition_plan` error

### Python — compose with plan

```python
from elevenlabs.client import ElevenLabs

elevenlabs = ElevenLabs()

composition_plan = {
    "chunks": [
        {
            "text": "[Verse]\nWalking down an empty street\nWondering who I'll meet",
            "duration_ms": 15000,
            "positive_styles": ["pop", "upbeat", "female vocals", "acoustic guitar"],
            "negative_styles": ["dark", "slow"],
            "context_adherence": "high",
        },
        {
            "text": "[Chorus]\nThis is my moment\nI won't let it go",
            "duration_ms": 15000,
            "positive_styles": ["powerful vocals", "full band"],
            "negative_styles": [],
            "context_adherence": "high",
        },
    ]
}

audio = elevenlabs.music.compose(
    composition_plan=composition_plan,
    model_id="music_v2",
)

with open("output.mp3", "wb") as f:
    for chunk in audio:
        f.write(chunk)
```

### TypeScript — compose with plan

```typescript
import { ElevenLabsClient } from "@elevenlabs/elevenlabs-js";

const elevenlabs = new ElevenLabsClient();

const compositionPlan = {
  chunks: [
    {
      text: "[Verse]\nWalking down an empty street\nWondering who I'll meet",
      durationMs: 15000,
      positiveStyles: ["pop", "upbeat", "female vocals", "acoustic guitar"],
      negativeStyles: ["dark", "slow"],
      contextAdherence: "high",
    },
    {
      text: "[Chorus]\nThis is my moment\nI won't let it go",
      durationMs: 15000,
      positiveStyles: ["powerful vocals", "full band"],
      negativeStyles: [],
      contextAdherence: "high",
    },
  ],
};

const audio = await elevenlabs.music.compose({
  compositionPlan,
  modelId: "music_v2",
});
```

### Generate a plan from a prompt, then modify

```python
plan = elevenlabs.music.composition_plan.create(
    prompt="An upbeat pop song about summer adventures",
    music_length_ms=60000,
    model_id="music_v2",
)

plan["chunks"][0]["text"] = "[Verse 1]\nCustom lyrics here"

audio = elevenlabs.music.compose(composition_plan=plan, model_id="music_v2")
```

```typescript
const plan = await elevenlabs.music.compositionPlan.create({
  prompt: "An upbeat pop song about summer adventures",
  musicLengthMs: 60000,
  modelId: "music_v2",
});

plan.chunks[0].text = "[Verse 1]\nCustom lyrics here";

const audio = await elevenlabs.music.compose({
  compositionPlan: plan,
  modelId: "music_v2",
});
```

---

## 7. Music Inpainting

Edit specific parts of a song while keeping the rest intact. Uses `music_v2`.

Two chunk types in an inpainting plan:
- **Generation chunk** — new audio from text + styles
- **Audio reference chunk** — inserts a stored song slice unchanged (`song_id` + `range`)

### Store a song for inpainting

**Option A: Generate and store**

```python
response = elevenlabs.music.compose_detailed(
    prompt="An upbeat pop song",
    music_length_ms=60000,
    model_id="music_v2",
    store_for_inpainting=True,
)
song_id = response.song_id

with open("original.mp3", "wb") as f:
    f.write(response.audio)
```

**Option B: Upload existing file**

```python
response = elevenlabs.music.upload(
    file=open("my-song.mp3", "rb"),
    extract_composition_plan="music_v2",
)
song_id = response.song_id
composition_plan = response.composition_plan
```

### Keep + regenerate sections — Python

```python
composition_plan = {
    "chunks": [
        {"song_id": song_id, "range": {"start_ms": 0, "end_ms": 30000}},
        {
            "text": "[Chorus]\nWe're rising up tonight\nNothing can stop us now",
            "duration_ms": 30000,
            "positive_styles": ["bigger drums", "layered vocals", "anthemic"],
            "negative_styles": ["sparse", "minimal"],
            "context_adherence": "high",
        },
    ]
}

audio = elevenlabs.music.compose(
    composition_plan=composition_plan,
    model_id="music_v2",
)

with open("edited.mp3", "wb") as f:
    for chunk in audio:
        f.write(chunk)
```

### Keep + regenerate sections — TypeScript

```typescript
const compositionPlan = {
  chunks: [
    { songId, range: { startMs: 0, endMs: 30000 } },
    {
      text: "[Chorus]\nWe're rising up tonight\nNothing can stop us now",
      durationMs: 30000,
      positiveStyles: ["bigger drums", "layered vocals", "anthemic"],
      negativeStyles: ["sparse", "minimal"],
      contextAdherence: "high",
    },
  ],
};

const audio = await elevenlabs.music.compose({
  compositionPlan,
  modelId: "music_v2",
});
```

### Conditioning

Condition a generation chunk on a stored audio slice to carry over musical
characteristics. `condition_strength`: `low`, `medium` (default), `high`, `xhigh`.

```python
{
    "text": "[Chorus]\nThis is my moment",
    "duration_ms": 15000,
    "positive_styles": ["powerful vocals", "full band"],
    "context_adherence": "high",
    "conditioning_ref": {
        "song_id": "<SONG_ID>",
        "range": {"start_ms": 0, "end_ms": 10000},
    },
    "condition_strength": "high",
}
```

The first chunk with `conditioning_ref` shapes the entire song.
Max conditioning reference length: 30,000 ms.

### Inpainting patterns

| Pattern           | How                                                                           |
| ----------------- | ----------------------------------------------------------------------------- |
| Edit one section  | Audio ref for kept parts + generation chunk for the edited section             |
| Extend a song     | New generation intro + audio ref for core + new generation outro               |
| Seamless loop     | Audio ref slice + generation "glue" chunk + same audio ref slice again         |
| Generate similar  | First generation chunk with `conditioning_ref` on original, rest follows      |

### Constraints

| Constraint                     | Value                 |
| ------------------------------ | --------------------- |
| Max chunks per plan            | 30                    |
| Min chunk duration             | 3,000 ms              |
| Max chunk duration             | 120,000 ms            |
| Max conditioning reference     | 30,000 ms             |
| Min time range                 | 50 ms                 |
| Total duration range           | 3 s – 10 min          |

---

## Common Voice IDs (examples)

These are example IDs from the docs — replace with actual voice IDs from your
account or the Voice Library:

- `aMSt68OGf4xUZAnLpTU8` — example voice
- `T7QGPtToiqH4S8VlIkMJ` — example voice
- `JBFqnCBsd6RMkjVDRZzb` — example voice (George)

---

## Environment setup

Both SDKs read `ELEVENLABS_API_KEY` from the environment. Set it in `.env` or
export it directly:

```bash
export ELEVENLABS_API_KEY="your_api_key_here"
```

Python: `pip install elevenlabs python-dotenv`
TypeScript: `npm install @elevenlabs/elevenlabs-js dotenv`

For audio playback, you may need [MPV](https://mpv.io/) and/or
[ffmpeg](https://ffmpeg.org/).
