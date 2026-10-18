import { Box, ButtonBase, Popover, Tab, Tabs, Typography } from '@mui/material';
import { useState } from 'react';
import { t } from '../i18n';
import { readLocalJson, writeLocal } from '../storage';

const RECENT_KEY = 'unomail.emoji.recent';
const RECENT_MAX = 24;

/** The emoji offered, by category. Plain code points only, so every system can show them. */
const CATEGORIES: { id: string; label: () => string; icon: string; emoji: string }[] = [
  { id: 'smileys', label: () => t('Smileys'), icon: '😀', emoji: '😀 😃 😄 😁 😆 😅 🤣 😂 🙂 🙃 😉 😊 😇 🥰 😍 🤩 😘 😗 😚 😙 😋 😛 😜 🤪 😝 🤑 🤗 🤭 🤫 🤔 🤐 🤨 😐 😑 😶 😏 😒 🙄 😬 😌 😔 😪 😴 😷 🤒 🤕 🤢 🤮 🥵 🥶 😵 🤯 🤠 🥳 😎 🤓 🧐 😕 😟 🙁 😮 😯 😲 😳 🥺 😦 😧 😨 😰 😥 😢 😭 😱 😖 😣 😞 😓 😩 😫 🥱 😤 😡 😠 🤬 😈 💀 💩 🤡 👻 👽 🤖' },
  { id: 'people', label: () => t('People'), icon: '👋', emoji: '👋 🤚 ✋ 🖖 👌 🤏 ✌️ 🤞 🤟 🤘 🤙 👈 👉 👆 👇 ☝️ 👍 👎 ✊ 👊 🤛 🤜 👏 🙌 👐 🤲 🤝 🙏 ✍️ 💪 👀 🧠 👶 🧒 👦 👧 🧑 👨 👩 🧓 👴 👵 🙋 🙆 🙅 🤷 🤦 💁 🙇 👮 🧑‍💻 🧑‍🍳 🧑‍🏫 🧑‍⚕️ 🧑‍🎓 💃 🕺 👫 👪' },
  { id: 'nature', label: () => t('Nature'), icon: '🌿', emoji: '🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🐔 🐧 🐦 🦆 🦉 🐴 🦄 🐝 🦋 🐌 🐞 🐢 🐍 🐙 🐬 🐳 🐟 🌵 🎄 🌲 🌳 🌴 🌱 🌿 🍀 🍁 🍂 🌷 🌹 🌺 🌸 🌼 🌻 🌞 🌝 🌙 ⭐ 🌟 ⚡ 🔥 🌈 ☀️ ⛅ ☁️ 🌧️ ⛄ ❄️ 💧 🌊' },
  { id: 'food', label: () => t('Food'), icon: '🍔', emoji: '🍏 🍎 🍐 🍊 🍋 🍌 🍉 🍇 🍓 🫐 🍒 🍑 🥭 🍍 🥥 🥝 🍅 🥑 🥦 🥕 🌽 🥔 🥐 🍞 🧀 🥚 🥓 🥩 🍗 🌭 🍔 🍟 🍕 🥪 🌮 🌯 🥗 🍝 🍜 🍣 🍱 🥟 🍦 🍰 🎂 🧁 🍫 🍬 🍩 🍪 ☕ 🍵 🧃 🥤 🍺 🍻 🥂 🍷 🍸' },
  { id: 'activities', label: () => t('Activities'), icon: '⚽', emoji: '⚽ 🏀 🏈 ⚾ 🎾 🏐 🏉 🎱 🏓 🏸 🥅 ⛳ 🏹 🎣 🥊 🎽 ⛸️ 🎿 🏂 🏋️ 🚴 🏊 🧗 🏆 🥇 🥈 🥉 🏅 🎖️ 🎫 🎪 🎭 🎨 🎬 🎤 🎧 🎼 🎹 🥁 🎷 🎺 🎸 🎻 🎲 🧩 🎯 🎳 🎮 🎉 🎊 🎈 🎁 🎀 ✈️ 🚗 🚲 🚀 🏖️ 🏔️ 🏠' },
  { id: 'objects', label: () => t('Objects'), icon: '💡', emoji: '⌚ 📱 💻 ⌨️ 🖥️ 🖨️ 🖱️ 💾 📷 📹 🎥 📞 ☎️ 📺 📻 ⏰ ⏳ 🔋 🔌 💡 🔦 🕯️ 💸 💵 💳 💎 🔧 🔨 🛠️ 🔩 ⚙️ 🔑 🗝️ 🔒 🔓 📦 📫 📬 📮 ✉️ 📧 📨 📝 📄 📃 📑 📊 📈 📉 📅 📆 📌 📎 ✂️ 🖊️ ✏️ 📚 📖 🔖 🏷️ 🛒 🧾' },
  { id: 'symbols', label: () => t('Symbols'), icon: '❤️', emoji: '❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❣️ 💕 💞 💓 💗 💖 💘 💝 ✅ ☑️ ✔️ ❌ ❎ ➕ ➖ ➗ ✖️ ❓ ❔ ❗ ❕ ‼️ ⁉️ 💯 🔴 🟠 🟡 🟢 🔵 🟣 ⚫ ⚪ 🟥 🟩 🟦 ⬛ ⬜ 🔶 🔷 ⚠️ 🚫 ⛔ ♻️ 🔁 🔄 ▶️ ⏸️ ⏹️ ⏩ ⏪ 🆗 🆕 🆒 ℹ️ 🔔 💤' },
];

/** A popover of emoji; the chosen one is handed to `onPick`, and remembered on this device. */
export function EmojiPicker({ anchor, onClose, onPick }: { anchor: HTMLElement | null; onClose: () => void; onPick: (emoji: string) => void }) {
  const [recent, setRecent] = useState<string[]>(() => readLocalJson<string[]>(RECENT_KEY, []));
  const [tab, setTab] = useState(() => (recent.length ? 'recent' : CATEGORIES[0].id));
  const shown = tab === 'recent' ? recent : (CATEGORIES.find((c) => c.id === tab) ?? CATEGORIES[0]).emoji.split(' ');
  const pick = (emoji: string) => {
    const next = [emoji, ...recent.filter((e) => e !== emoji)].slice(0, RECENT_MAX);
    setRecent(next);
    writeLocal(RECENT_KEY, JSON.stringify(next));
    onPick(emoji);
  };
  return (
    <Popover
      open={Boolean(anchor)}
      anchorEl={anchor}
      onClose={onClose}
      anchorOrigin={{ vertical: 'top', horizontal: 'left' }}
      transformOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      slotProps={{ paper: { sx: { width: 340, borderRadius: 3 } } }}
    >
      <Tabs value={tab} onChange={(_, value: string) => setTab(value)} variant="scrollable" scrollButtons={false} aria-label={t('Insert emoji')} sx={{ minHeight: 40, borderBottom: 1, borderColor: 'divider', '& .MuiTab-root': { minWidth: 40, minHeight: 40, px: 1, fontSize: 20 } }}>
        {recent.length > 0 && <Tab value="recent" label="🕘" aria-label={t('Recently used')} />}
        {CATEGORIES.map((category) => (
          <Tab key={category.id} value={category.id} label={category.icon} aria-label={category.label()} />
        ))}
      </Tabs>
      <Typography variant="caption" color="text.secondary" component="p" sx={{ px: 1.5, pt: 1 }}>
        {tab === 'recent' ? t('Recently used') : CATEGORIES.find((c) => c.id === tab)?.label()}
      </Typography>
      <Box role="listbox" aria-label={t('Insert emoji')} sx={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', p: 1, maxHeight: 248, overflowY: 'auto' }}>
        {shown.map((emoji) => (
          <ButtonBase key={emoji} role="option" aria-label={emoji} aria-selected={false} onClick={() => pick(emoji)} sx={{ fontSize: 24, lineHeight: 1, aspectRatio: '1', borderRadius: 2, '&:hover, &:focus-visible': { bgcolor: 'action.hover' } }}>
            {emoji}
          </ButtonBase>
        ))}
      </Box>
    </Popover>
  );
}
