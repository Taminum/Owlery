-- Commands the owner keeps ready for the terminal, one list for Linux machines and one for Windows machines, shared by the whole
-- panel. "danger" asks for a confirmation before one is run in a single step.
CREATE TABLE command_templates (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    os         text        NOT NULL CHECK (os IN ('linux', 'windows')),
    name       text        NOT NULL,
    command    text        NOT NULL,
    note       text        NOT NULL DEFAULT '',
    danger     boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (os, name)
);

INSERT INTO command_templates (os, name, command, note, danger) VALUES
 ('linux', 'Контейнеры', 'docker ps -a', 'Все контейнеры и в каком они состоянии', false),
 ('linux', 'Диск занят', E'df -h\ndu -xh / --max-depth=1 2>/dev/null | sort -h | tail -15', 'Разделы и самые тяжёлые папки', false),
 ('linux', 'Кто слушает порты', 'ss -tlnp', '', false),
 ('linux', 'Память', E'free -h\nps aux --sort=-%mem | head -10', 'Свободная память и кто её ест', false),
 ('linux', 'Кто грузит процессор', 'ps aux --sort=-%cpu | head -10', '', false),
 ('linux', 'Упавшие службы', 'systemctl --failed', '', false),
 ('linux', 'Ошибки журнала за час', 'journalctl -p err --since "1 hour ago" --no-pager | tail -50', '', false),
 ('linux', 'Последние входы', 'last -n 15', '', false),
 ('linux', 'Fail2ban: кто забанен', 'fail2ban-client status sshd', '', false),
 ('linux', 'Обновления', 'apt list --upgradable 2>/dev/null | head -30', 'Только список, ничего не ставит', false),
 ('linux', 'Время', 'timedatectl', '', false),
 ('linux', 'Перезапуск Docker', 'systemctl restart docker', 'Остановит контейнеры на несколько секунд', true),
 ('linux', 'Перезагрузка', 'reboot', 'Машина уйдёт на перезагрузку', true);
