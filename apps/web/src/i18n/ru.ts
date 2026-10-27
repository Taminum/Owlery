import { m1 } from './ru.m1'
import { intel } from './ru.intel'
import { intel2 } from './ru.intel2'
import { awgText } from './ru.awg'
import { securityText } from './ru.security'
import { dnsText } from './ru.dns'
import { digestText } from './ru.digest'
import { kawaiiText } from './ru.kawaii'
import { billingText } from './ru.billing'
import { hostsText } from './ru.hosts'
import { notifyTuneText } from './ru.notifytune'
import { startText } from './ru.start'
import { serversText } from './ru.servers'
// All UI text lives here so a second locale can be added without touching components.
const base = {
  'app.name': 'RemnaScope',
  'app.tagline': 'Аналитика трафика',

  'nav.overview': 'Обзор',
  'nav.traffic': 'Аналитика трафика',
  'nav.domains': 'Домены и сервисы',
  'nav.users': 'Пользователи',
  'nav.nodes': 'Ноды',
  'nav.devices': 'Устройства',
  'nav.channels': 'Каналы',
  'nav.live': 'Сейчас',
  'nav.sites': 'Сайты',
  'nav.panels': 'Панели',
  'nav.alerts': 'Оповещения',
  'nav.settings': 'Настройки',
  'nav.soon': 'скоро',
  'nav.menu': 'Меню',
  'nav.close': 'Закрыть меню',

  'demo.banner': 'ДЕМО-ДАННЫЕ',
  'demo.bannerText': 'Синтетические данные для проверки интерфейса. Это не реальный трафик и не реальные панели.',
  'demo.mode': 'Демо-режим · без входа',

  'filter.panel': 'Панель',
  'filter.panelAll': 'Все доступные',
  'filter.nodes': 'Ноды',
  'filter.nodesAll': 'Все ноды',
  'filter.nodesSelected': 'Выбрано: {n}',
  'filter.more': 'Период, часовой пояс и обновление',
  'filter.range': 'Период',
  'filter.custom': 'Свой период',
  'filter.from': 'С',
  'filter.to': 'По',
  'filter.apply': 'Применить',
  'filter.tz': 'Часовой пояс',
  'filter.tzLocal': 'Локальный',
  'filter.refresh': 'Автообновление',
  'filter.refreshShort': 'Авто',
  'filter.refreshOff': 'Выкл',
  'filter.refreshNow': 'Обновить',
  'filter.reset': 'Сбросить фильтры',
  'range.15m': '15 минут',
  'range.1h': '1 час',
  'range.24h': '24 часа',
  'range.7d': '7 дней',
  'range.30d': '30 дней',
  'range.custom': 'Свой',
  'scope.all': 'Агрегат по всем панелям',
  'scope.single': 'Панель: {name}',
  'scope.multi': 'Панели: {n}',

  'kpi.connections': 'Принятые соединения',
  'kpi.connectionsNote': 'строки access-лога, не визиты',
  'kpi.hosts': 'Уникальные хосты',
  'kpi.ips': 'Уникальные IP',
  'kpi.nodes': 'Ноды с данными',
  'kpi.traffic': 'Трафик (счётчики панели)',
  'kpi.freshness': 'Свежесть сбора',
  'kpi.fresh': 'Последнее событие {t}',
  'kpi.lag': 'отставание {s} с',
  'kpi.stale': 'Данные устарели',
  'kpi.vsPrev': 'к прошлому периоду',
  'kpi.down': 'вход',
  'kpi.up': 'выход',

  'chart.timeline': 'Принятые соединения по времени',
  'chart.traffic': 'Трафик по времени',
  'chart.trafficNote': 'байты · счётчики API панели',
  'chart.users': 'Соединения по пользователям',
  'chart.connections': 'соединений',
  'chart.gap': 'Нет данных сбора',
  'chart.tcp': 'TCP',
  'chart.udp': 'UDP',

  'table.hosts': 'Топ хостов назначения',
  'table.ips': 'Топ IP назначения',
  'table.ports': 'Топ портов',
  'table.services': 'Сервисы',
  'table.recent': 'Последние соединения',
  'table.countries': 'Страны (по IP)',
  'table.num': '#',
  'table.host': 'Хост',
  'table.ip': 'IP',
  'table.port': 'Порт',
  'table.service': 'Сервис',
  'table.confidence': 'Уверенность',
  'table.connections': 'Соединений',
  'table.share': 'Доля',
  'table.time': 'Время',
  'table.panel': 'Панель',
  'table.node': 'Нода',
  'table.user': 'Пользователь',
  'table.proto': 'Протокол',
  'table.dest': 'Назначение',
  'table.other': 'остальные',
  'table.system': 'система',
  'conf.high': 'высокая',
  'conf.medium': 'средняя',
  'conf.low': 'низкая',

  'countries.empty': 'Страны по IP появятся, когда подключим проверенный источник GeoIP. Без него мы ничего не угадываем.',
  'countries.action': 'Что для этого нужно',

  'coverage.partial': 'Сбор неполный: покрытие {pct}',
  'coverage.gap': '{node}: нет данных {from}–{to}',
  'coverage.full': 'Покрытие сбора {pct}',

  'state.loading': 'Загружаем данные',
  'state.noData.title': 'Нет данных за выбранный период',
  'state.noData.text': 'События ещё не поступали или фильтр слишком узкий. Данные не придумываем.',
  'state.noData.action': 'Расширить период до 7 дней',
  'state.pending.title': 'Синхронизация ещё не завершена',
  'state.pending.text': 'Панель подключена, но первая синхронизация не закончилась. Это не то же самое, что «нет данных».',
  'state.pending.action': 'Проверить снова',
  'state.error.title': 'API недоступен',
  'state.error.text': 'Не удалось получить данные. Это ошибка соединения, а не пустой результат.',
  'state.error.retry': 'Повторить',
  'state.error.id': 'Код запроса: {id}',
  'state.forbidden.title': 'Нет доступа к панели',
  'state.forbidden.text': 'Выбранная панель вам недоступна.',
  'state.forbidden.action': 'Сбросить фильтры',
  'state.invalid.title': 'Некорректный фильтр',
  'state.invalid.text': 'Параметры периода или нод не подходят друг другу.',
  'state.invalid.action': 'Сбросить фильтры',

  'placeholder.title': 'Раздел в разработке',
  'placeholder.text': 'Этот раздел появится в одном из следующих этапов. Сейчас доступен обзор на демо-данных.',
  'placeholder.action': 'Вернуться к обзору',
  'placeholder.milestone': 'Этап: {m}',

  'a11y.skip': 'К основному содержимому',
  'a11y.statusOk': 'норма',
  'a11y.statusLag': 'отстаёт',
} as const

export const ru = { ...base, ...m1, ...intel, ...intel2, ...awgText, ...securityText, ...dnsText, ...digestText, ...kawaiiText, ...billingText, ...hostsText, ...notifyTuneText, ...startText, ...serversText } as const

export type MsgKey = keyof typeof ru
