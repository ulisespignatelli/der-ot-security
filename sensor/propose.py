"""Propone cambios a una política a partir de lo observado, sin aplicarlos.

`learn` escribe una política desde cero. `propose` es para cuando ya hay una
en uso: compara lo que la política permite con lo que una captura muestra, y
devuelve una propuesta y un informe de qué cambiaría.

La propuesta nunca toca la política vigente, y solo **agrega** lo que haría
falta para que esa captura no genere alertas. Lo que la política permite y la
captura no muestra se informa como candidato a quitar, pero no se quita: que
algo no aparezca en media hora de tráfico no prueba que no se use.

Cada cambio se marca por su efecto, que es lo que un ingeniero tiene que
mirar antes de aceptarlo:

  afloja    la política pasaría a permitir algo que hoy genera una alerta
  revisar   la política permite algo que esta captura no mostró
"""
import copy

from .baseline import learn


def _entry(effect, area, detail, evidence=""):
    return {"effect": effect, "area": area, "detail": detail, "evidence": evidence}


def compare(current, observed):
    """Devuelve (propuesta, cambios) entre la política vigente y la observada."""
    proposal, changes = copy.deepcopy(current), []

    # --- maestros autorizados ---
    allowed = list(proposal.get("authorized_masters", []))
    for ip in observed["authorized_masters"]:
        if ip not in allowed:
            allowed.append(ip)
            changes.append(_entry("afloja", "maestros", f"Autorizar a {ip} como maestro",
                                  "Envía solicitudes Modbus y hoy dispara R1 y R2"))
    for ip in proposal.get("authorized_masters", []):
        if ip not in observed["authorized_masters"]:
            changes.append(_entry("revisar", "maestros", f"{ip} está autorizado y no aparece",
                                  "Quitarlo solo si se confirma que ya no se usa"))
    if "authorized_masters" in proposal or allowed:
        proposal["authorized_masters"] = sorted(allowed)

    # --- esclavos: funciones y registros escritos ---
    slaves = proposal.setdefault("slaves", {}) if "slaves" in proposal or observed["slaves"] else {}
    for ip, seen in observed["slaves"].items():
        known = slaves.get(ip)
        if known is None:
            slaves[ip] = copy.deepcopy(seen)
            changes.append(_entry("afloja", "esclavos", f"Agregar el esclavo {ip} a la línea base",
                                  f"Responde a las funciones {seen['function_codes']} y hoy dispara R11"))
            continue
        for code in seen["function_codes"]:
            if code not in known.get("function_codes", []):
                known.setdefault("function_codes", []).append(code)
                known["function_codes"].sort()
                changes.append(_entry("afloja", "esclavos", f"Aceptar la función {code} hacia {ip}",
                                      "Hoy dispara R9 por no figurar en la línea base"))
        ranges = known.setdefault("write_ranges", {})
        for reg, seen_range in seen.get("write_ranges", {}).items():
            known_range = ranges.get(reg)
            if known_range is None:
                ranges[reg] = dict(seen_range)
                changes.append(_entry("afloja", "escrituras", f"Permitir escrituras al registro {reg} de {ip}",
                                      f"Se observaron valores de {seen_range['min']} a {seen_range['max']}; hoy dispara R10"))
            elif seen_range["min"] < known_range["min"] or seen_range["max"] > known_range["max"]:
                widened = {"min": min(known_range["min"], seen_range["min"]),
                           "max": max(known_range["max"], seen_range["max"])}
                changes.append(_entry("afloja", "escrituras",
                                      f"Ampliar el registro {reg} de {ip} de {known_range['min']}–{known_range['max']} "
                                      f"a {widened['min']}–{widened['max']}",
                                      "Hoy los valores fuera del rango disparan R3"))
                ranges[reg] = widened
        for code in known.get("function_codes", []):
            if code not in seen["function_codes"]:
                changes.append(_entry("revisar", "esclavos", f"La función {code} hacia {ip} no aparece", ""))
    for ip in list(slaves):
        if ip not in observed["slaves"]:
            changes.append(_entry("revisar", "esclavos", f"El esclavo {ip} está en la línea base y no aparece", ""))
    if slaves:
        proposal["slaves"] = slaves

    # --- direcciones físicas ---
    macs = proposal.setdefault("hardware_addresses", {}) if "hardware_addresses" in proposal or observed.get("hardware_addresses") else {}
    for ip, seen_macs in observed.get("hardware_addresses", {}).items():
        known_macs = macs.get(ip)
        if known_macs is None:
            macs[ip] = list(seen_macs)
        else:
            for mac in seen_macs:
                if mac not in known_macs:
                    known_macs.append(mac)
                    changes.append(_entry("afloja", "direcciones físicas",
                                          f"Aceptar {mac} como dirección física de {ip}",
                                          "Hoy dispara R12. Confirmar que es un reemplazo de equipo y no una suplantación"))
    if macs:
        proposal["hardware_addresses"] = macs

    # --- límite de tasa ---
    current_rate = proposal.get("max_requests_per_second")
    observed_rate = observed["max_requests_per_second"]
    if current_rate is None:
        proposal["max_requests_per_second"] = observed_rate
        changes.append(_entry("afloja", "tasa", f"Fijar el límite en {observed_rate} solicitudes por segundo", ""))
    elif observed_rate > current_rate:
        proposal["max_requests_per_second"] = observed_rate
        changes.append(_entry("afloja", "tasa", f"Subir el límite de {current_rate} a {observed_rate} solicitudes por segundo",
                              "El tráfico observado supera el límite vigente y dispara R7"))
    elif observed_rate < current_rate:
        changes.append(_entry("revisar", "tasa", f"El límite vigente es {current_rate} y el pico observado fue {observed_rate}",
                              "Bajarlo endurecería la detección, a costa de más falsos positivos"))

    changes.sort(key=lambda c: (c["effect"] != "afloja", c["area"], c["detail"]))
    return proposal, changes


def propose(capture, current=None, port=502):
    observed = learn(capture, port=port)
    proposal, changes = compare(current or {"modbus_port": port}, observed)
    proposal.setdefault("comment", "Propuesta generada por el sensor. Revisar cada cambio antes de aplicarla.")
    proposal["proposed_from"] = observed["learned_from"]
    return {"proposal": proposal, "changes": changes, "observed": observed}
