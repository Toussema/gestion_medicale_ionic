import { Component, OnInit } from '@angular/core';
import { DocumentsService } from '../../services/documents.service';
import { AuthService } from '../../services/auth.service';
import { IonicModule, PopoverController } from '@ionic/angular';
import { CommonModule } from '@angular/common';
import { Router } from '@angular/router';

@Component({
  selector: 'app-notifications',
  templateUrl: './notifications.component.html',
  styleUrls: ['./notifications.component.css'],
  standalone: true,
  imports: [IonicModule, CommonModule]
})
export class NotificationsComponent implements OnInit {
  notifications: any[] = [];

  constructor(
    private documentsService: DocumentsService,
    private authService: AuthService,
    private popoverController: PopoverController,
    private router: Router
  ) {}

  ngOnInit() {
    this.loadNotifications();
  }

  loadNotifications() {
    const hidden = JSON.parse(localStorage.getItem('hiddenNotifs') || '[]');

    this.documentsService.getNotifications().subscribe({
      next: (data) => {
        this.notifications = data.filter((notif: any) => !hidden.includes(notif.id));
      },
      error: (err) => console.error(err)
    });
  }

  markAsRead(notifId: string) {
    this.documentsService.markNotificationRead(notifId).subscribe({
      next: () => {
        this.loadNotifications();
      },
      error: (err) => console.error(err)
    });
  }

  async closePopover() {
    // Retirer le focus avant de fermer
    const activeElement = document.activeElement as HTMLElement;
    if (activeElement) {
      activeElement.blur();
    }
    await this.popoverController.dismiss();
  }

  removeNotification(notifId: string) {
    const hidden = JSON.parse(localStorage.getItem('hiddenNotifs') || '[]');
    if (!hidden.includes(notifId)) {
      hidden.push(notifId);
      localStorage.setItem('hiddenNotifs', JSON.stringify(hidden));
    }
    this.notifications = this.notifications.filter(notif => notif.id !== notifId);
  }

  async navigateTo(route: string) {
    // Retirer le focus avant de naviguer
    const activeElement = document.activeElement as HTMLElement;
    if (activeElement) {
      activeElement.blur();
    }
    await this.router.navigate([route]);
    await this.popoverController.dismiss();
  }
}