package alerts

import (
	"fmt"
	"time"

	"github.com/Taminum/Owlery/internal/store"
)

const (
	// ContainerRestarts is how many restarts within an hour make a container "keeps restarting".
	ContainerRestarts = 3
	// containerGrace is how long a stopped container is left alone: recreating one (docker compose up) stops it for a moment.
	containerGrace = 2 * time.Minute
)

// DockerConditions lists the containers that keep restarting and the ones that should always run but have stopped. A
// container whose restart policy is "no" or one stopped on purpose by a person with "unless-stopped" is the same thing to
// the machine, so the owner who wants quiet puts that alert off for a while.
func DockerConditions(states []store.DockerAlertState, now time.Time) []store.Condition {
	var out []store.Condition
	for _, h := range states {
		for _, c := range h.Containers {
			subject := h.VPSID + ":" + c.Name
			switch {
			case c.State == "restarting" || c.Restarts1h >= ContainerRestarts:
				detail := fmt.Sprintf("перезапусков за последний час: %d, код выхода %d", c.Restarts1h, c.Exit)
				if c.State == "restarting" {
					detail = "сейчас перезапускается; " + detail
				}
				out = append(out, store.Condition{Kind: store.AlertHostContainer, Subject: subject, Label: "Контейнер перезапускается: " + c.Name + " (" + h.Name + ")", Detail: detail})
			case (c.State == "exited" || c.State == "dead") && (c.Policy == "always" || c.Policy == "unless-stopped") &&
				(c.Finished == nil || now.Sub(*c.Finished) > containerGrace):
				detail := fmt.Sprintf("остановлен, код выхода %d, а политика перезапуска «%s»", c.Exit, c.Policy)
				if c.Finished != nil {
					detail = "остановлен " + minutes(now.Sub(*c.Finished)) + " назад, код выхода " + fmt.Sprint(c.Exit) + ", а политика перезапуска «" + c.Policy + "»"
				}
				out = append(out, store.Condition{Kind: store.AlertHostContainerDown, Subject: subject, Label: "Контейнер остановлен: " + c.Name + " (" + h.Name + ")", Detail: detail})
			}
		}
	}
	return out
}
