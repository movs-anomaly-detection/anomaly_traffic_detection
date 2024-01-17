
import asyncio
import logging
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, StateFilter
from aiogram.types import Message, FSInputFile
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext
from catboost import CatBoostClassifier
import pickle
import csv
import pandas as pd
import joblib
from datetime import datetime
from config_reader import config

#bot = Bot(token=BOT_TOKEN)
bot = Bot(token=config.bot_token.get_secret_value())
dp = Dispatcher()
dp["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")

pickled_model = pickle.load(open('model_and_scaler\\ctb_model.pkl', 'rb'))
scaler = joblib.load('model_and_scaler\\std_scaler.bin')


class JsonFileState(StatesGroup):
   downloading_json = State()

class CVSFileState(StatesGroup):
   downloading_csv = State()


def json_to_df():
   with open('for_docs\\json_for_predict.json', encoding='utf-8') as inputfile:
      df = pd.read_json(inputfile, typ='series')
   return df

def preprocecc_with_scaler_csv(df):
   df = df[['addr', 'proto', 'num_timestamps', 'mean_timestamps', 'median_timestamps', 'country']]
   df = df.fillna(0)
   df = df.merge(pd.DataFrame(list(df['addr'].str.split('.').values), columns=['addr_1','addr_2','addr_3','addr_4']), left_index=True, right_index=True)
   df = df.drop(['addr_3', 'addr_4', 'addr'], axis=1)
   df = pd.concat([df[['proto', 'country', 'addr_1','addr_2']].reset_index(), pd.DataFrame(scaler.transform(df[['num_timestamps', 'mean_timestamps', 'median_timestamps']]),columns=['num_timestamps', 'mean_timestamps', 'median_timestamps'])], axis=1)
   df = df.drop('index', axis=1)
   return df


@dp.message(Command("start"))
async def start(message: Message):
   await message.answer(f"Добрейший вечерочек, {message.from_user.first_name}, с тобой бот для определения Аномальностей в обращении к интернет-ресурсам")

@dp.message(StateFilter(None), Command("one_object"))
async def one_object(message: Message, state: FSMContext):
   await message.answer(text="Загрузи .json как документ. JSON следующего вида: \n{'proto': 'string',\n'country': 'string',\n'addr_1': int,\n'addr_2': int,\n'num_timestamps': float,\n'mean_timestamps': float,\n'median_timestamps': float}\n\nОбрати внимание:\n1) proto - содержит название протокола\n2) country - содержит название страны с Заглавной\n3) addr_1 - содержит первые цифры id адреса ресурса\n4) addr_2 - содержит вторые цифры ip адреса ресурса\n5) num_timestamps - содержит значение количества таймстемпов по соединению\n6) mean_timestamps - содержит среднее время между таймстемпами по соединению\n7) median_timestamps - содержит медианное время между таймстемпами по соединению\n\nnum_timestamps, mean_timestamps и median_timestamps должны быть УЖЕ скаляризированы")
   await state.set_state(JsonFileState.downloading_json)

@dp.message(JsonFileState.downloading_json, F.document)
async def download_json(message: Message, bot:Bot, state: FSMContext):
   await bot.download(
      message.document,
      destination=f"for_docs\\json_for_predict.json"
   )
   df_object = json_to_df()
   predict = pickled_model.predict(df_object)
   texxt = "Безопасное соединение" if predict == 0 else "Опасное соединение"
   await message.answer(text=texxt)
   await state.clear()

@dp.message(StateFilter(None), Command("many_objects"))
async def many_objects(message: Message, state: FSMContext):
   await message.answer(text="Загрузи .csv как документ. Csv с соединениями следующего вида:\naddr,port,proto,num_timestamps,mean_timestamps,median_timestamps,country\nГде:\naddr - ip адрес\nport - порт\nproto - протокол\nnum_timestamps - содержит значение количества таймстемпов по соединению\nmean_timestamps - содержит среднее время между таймстемпами по соединению\nmedian_timestamps - содержит медианное время между таймстемпами по соединению\n\nnum_timestamps, mean_timestamps и median_timestamps должны быть НЕ скаляризированы")
   await state.set_state(CVSFileState.downloading_csv)

@dp.message(CVSFileState.downloading_csv, F.document)
async def download_csv(message: Message, bot:Bot, state: FSMContext):
   await bot.download(
      message.document,
      destination=f"for_docs\\csv_for_predict.csv"
   )
   datta = pd.read_csv('for_docs\\csv_for_predict.csv')
   preobraz_data = preprocecc_with_scaler_csv(datta)
   predict_list = pickled_model.predict(preobraz_data)
   predict_list_df = pd.Series(predict_list)
   datta_after_predict = datta.assign(predict=predict_list_df)
   datta_after_predict['predict'] = datta_after_predict['predict'].apply(lambda x: 'Опасное соединение' if x==1 else 'Безопасное соединение')
   datta_after_predict.to_csv('for_docs\\csv_AFTER_predict.csv', index=False)
   responz_csv = FSInputFile('for_docs\\csv_AFTER_predict.csv')
   await message.answer(text="В файле csv_AFTER_predict.csv содержится полученный на вход csv с добавленным столбцом, сообщающим статус Опасности соединения")
   await message.answer_document(responz_csv)
   await state.clear()


@dp.message(Command("help"))
async def help(message: Message):
   await message.answer(f"Бот принимает следующие команды:\n1) /start - бот поздоровается\n2) /one_object - для получения инфы об одном соединении. Загрузка данных ожидается в формате .json как документ\n3) /many_objects - для получения инфы о массиве соединений. Загрузка данных ожидается в формате .csv как документ\n4) /info - получить инфу об этой итерации жизни сервиса")

@dp.message(Command("info"))
async def cmd_info(message: types.Message, started_at: str):
    await message.answer(f"Бот запущен {started_at}")

@dp.message()
async def echo_message(message: Message):
   await bot.send_message(
      chat_id=message.chat.id,
      text="введи /help для инфы по взаимодействию с ботом")



async def main():
   logging.basicConfig(level=logging.DEBUG)
   await dp.start_polling(bot)

if __name__ == "__main__":
   asyncio.run(main())
