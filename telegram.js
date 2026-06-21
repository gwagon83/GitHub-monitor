const axios = require("axios");

async function sendTelegram(message) {

  await axios.post(
    `https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`,
    {
      chat_id: process.env.CHAT_ID,
      text: message
    }
  );

}

module.exports = sendTelegram;
