#!/bin/bash

SERVER_BIN="openssl-oqs"
CLIENT_BIN="openssl-oqs"
SERVER_PORT=4433

SERVER_CMD="$SERVER_BIN s_server \
  -cert test_dual_tls/server_rsa_cert.pem \
  -key test_dual_tls/server_rsa_key.pem \
  -pqcert test_dual_tls/server_pq_cert.pem \
  -pqkey test_dual_tls/server_pq_key.pem \
  -CAfile test_dual_tls/ca_cert.pem \
  -enable_dual_certs \
  -msg -debug -accept $SERVER_PORT"

CLIENT_CMD="$CLIENT_BIN s_client \
  -connect 127.0.0.1:$SERVER_PORT \
  -CAfile test_dual_tls/ca_dual.pem \
  -msg -debug"

echo "=== Lancement du serveur dual certificate ==="
echo "Commande serveur: $SERVER_CMD"
echo

$SERVER_CMD > server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "=== Lancement du client dual certificate ==="
echo "Commande client: $CLIENT_CMD"
echo

$CLIENT_CMD > client.log 2>&1

echo "=== Arrêt du serveur ==="
kill $SERVER_PID 2>/dev/null

echo
echo "=== Résumé serveur (server.log) ==="
echo "Dernières 20 lignes du log serveur:"
tail -n 20 server.log

echo
echo "=== Résumé client (client.log) ==="
echo "Dernières 20 lignes du log client:"
tail -n 20 client.log

echo
echo "=== Analyse des erreurs ==="
if grep -q "ERROR" server.log; then
    echo "❌ Erreurs détectées dans le log serveur:"
    grep "ERROR" server.log
else
    echo "✅ Aucune erreur détectée dans le log serveur"
fi

if grep -q "ERROR" client.log; then
    echo "❌ Erreurs détectées dans le log client:"
    grep "ERROR" client.log
else
    echo "✅ Aucune erreur détectée dans le log client"
fi

echo
echo "=== Vérification de la connexion ==="
if grep -q "CONNECTION CLOSED" client.log; then
    echo "❌ La connexion a été fermée prématurément"
elif grep -q "New, (NONE), Cipher is (NONE)" client.log; then
    echo "❌ Aucun chiffrement négocié"
elif grep -q "Verify return code: 0 (ok)" client.log; then
    echo "✅ Connexion établie avec succès"
else
    echo "⚠️  Statut de la connexion indéterminé"
fi

echo
echo "Pour voir tous les logs :"
echo "  less server.log"
echo "  less client.log" 