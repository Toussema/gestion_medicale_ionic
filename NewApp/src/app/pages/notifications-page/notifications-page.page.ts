import { Component, OnInit } from '@angular/core';
import { DocumentsService } from 'src/app/services/documents.service';

@Component({
  selector: 'app-notifications-page',
  templateUrl: './notifications-page.page.html',
  styleUrls: ['./notifications-page.page.scss'],
  standalone: false,
})
export class NotificationsPage implements OnInit {
  notifications: any[] = [];

  constructor(private documentsService: DocumentsService) {}

  ngOnInit() {
    this.loadNotifications();
  }

  loadNotifications() {
    // ❌ Ne plus filtrer avec localStorage
    this.documentsService.getNotifications().subscribe({
      next: (data) => {
        this.notifications = data;
      },
      error: (err) => console.error(err)
    });
  }

  markAsRead(notifId: string) {
    this.documentsService.markNotificationRead(notifId).subscribe(() => {
      this.loadNotifications();
    });
  }

  removeNotification(notifId: string) {
    // 👉 tu peux garder cette logique si tu veux permettre la suppression depuis cette page aussi
    const hidden = JSON.parse(localStorage.getItem('hiddenNotifs') || '[]');
    if (!hidden.includes(notifId)) {
      hidden.push(notifId);
      localStorage.setItem('hiddenNotifs', JSON.stringify(hidden));
    }
    // On n'applique plus le filtre ici
    // this.notifications = this.notifications.filter(notif => notif.id !== notifId);
  }
}
