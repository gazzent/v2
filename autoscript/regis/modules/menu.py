from regis import *

@bot.on(events.NewMessage(pattern=r"(?:.regis|/regis|/start)$"))
@bot.on(events.CallbackQuery(data=b'menu'))
async def menu(event):
	inline = [
[Button.inline(" REGIST ","registrasi"),
Button.inline(" EXTEND ","perpanjang")],
[Button.inline(" CHECK","cekip"),
Button.inline(" DELETE ","deleteip")]]
	sender = await event.get_sender()
	val = valid(str(sender.id))
	if val == "false":
		try:
			await event.answer("Akses Ditolak", alert=True)
		except:
			await event.reply("Akses Ditolak")
	elif val == "true":
		sh = f' curl -sS https://sc-xray.yha.my.id/ip | grep "###" | wc -l'
		ssh = subprocess.check_output(sh, shell=True).decode("ascii")

		msg = f"""
**◇ ━━━━━━━━  ◇**
**◇☘️AUTOSCRIPT☘️◇**
**◇ ━━━━━━━━  ◇**
**» List Harga :** 
🌸**1 BULAN 15k**
🍃**2 BULAN 25k**
🌻**3 BULAN 35K**
🐥**LIFE TIME 1IP 75K🐥**
**» Order :** @yha_bot
**◇ ━━━━━━━━  ◇**
**» Total Pelanggan :** `{ssh.strip()}`
"""
		x = await event.edit(msg,buttons=inline)
		if not x:
			await event.reply(msg,buttons=inline)

