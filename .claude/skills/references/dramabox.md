# DramaBox — Screenplay-Style Prompt Reference

DramaBox by Resemble AI uses a **screenplay-style prompt format** — no SSML,
no bracket tags. The prompt itself is the director's script. Stage directions
go outside quotes, dialogue goes inside quotes.

The model speaks the dialogue and interprets everything outside quotes as
performance direction — it never speaks stage directions aloud.

---

## Prompt format

```
<stage direction> "dialogue" <stage direction> "dialogue"
```

### Three components

| Component | Where | What the model does |
|---|---|---|
| **Dialogue** | Inside `"double quotes"` | Speaks it literally |
| **Stage directions** | Outside quotes | Interprets as performance cues (never spoken) |
| **Phonetic vocalizations** | Inside quotes, as single words | Produces the sound (laughing, gasps) |

---

## Stage direction examples

Place these outside quotes to shape delivery:

### Emotion

- `She speaks with cold fury`
- `His voice trembles with grief`
- `Warm enthusiasm creeping in`
- `Sinister calm`
- `Growing frustration`

### Pacing and timing

- `A long pause`
- `Speaking quickly, almost breathlessly`
- `Slowly, deliberately`
- `After a moment of hesitation`
- `Rapid-fire delivery`

### Vocal actions (outside quotes)

- `She sighs deeply`
- `He gulps nervously`
- `Her voice cracks`
- `He clears his throat`
- `She scoffs`
- `A sharp intake of breath`

### Volume and intensity

- `Almost whispering`
- `Voice rising to a shout`
- `Barely audible`
- `Voice softens`
- `With increasing intensity`

---

## Phonetic vocalizations (inside quotes)

When you want the model to produce a sound, write it as a single word inside
quotes:

**Do this:**
```
She can't help it. "Hahaha!" She wipes a tear.
```

**Don't do this:**
```
"Ha ha ha" — model will say each word separately
"Sigh" — model will say the word "sigh"
"Gasp" — model will say the word "gasp"
```

Vocalizations that work inside quotes: `"Hahaha"` `"Pfft"` `"Hmm"`
`"Ugh"` `"Mhm"` `"Ooh"` `"Ahh"` `"Whew"`

Actions that should stay **outside** quotes: sighs, gasps, coughs, clears
throat, gulps — these are stage directions, not words.

---

## Example scripts

### Emotional monologue

```
She stares at the letter, hands trembling.
"I knew this day would come."
A long pause. Her voice steadies.
"But I'm ready now."
She takes a deep breath, resolve building.
"Let them come. I'm not afraid anymore."
```

### Tense dialogue

```
He speaks through gritted teeth, barely controlled rage.
"You had one job."
A dangerous pause.
Almost whispering now.
"One. Simple. Job."
His voice suddenly erupts.
"And you couldn't even do that!"
```

### Narration with atmosphere

```
The narrator speaks softly, as though telling a bedside story.
"The old house had been empty for thirty years."
A pause. The tone shifts to something more unsettling.
"Or so everyone believed."
Voice drops to barely a whisper.
"But on nights like this... you could hear it breathing."
```

### Character with vocal events

```
He stumbles through the door, out of breath.
"Hahaha! You should have seen their faces!"
He catches his breath, still grinning.
"They didn't know what hit them."
His laughter fades. A moment of quiet reflection.
"But I wonder if it was worth it."
```

---

## Tips

- **One prompt controls everything:** speaker identity, emotion, delivery,
  laughs, sighs, breaths, pauses, and transitions
- **Think like a screenplay writer** — describe what the actor should feel and
  do, then write their lines
- **Emotional continuity:** DramaBox maintains emotional arcs across paragraphs
  rather than resetting at sentence boundaries
- **10-second voice cloning:** provide a short reference audio clip to clone
  a voice
- **Don't mix paradigms:** don't use `[bracket tags]` or SSML — DramaBox
  ignores them. Use stage directions instead
- **Keep directions concise** but descriptive — "voice breaking with barely
  contained grief" works better than a paragraph of instruction
